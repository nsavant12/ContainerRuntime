#!/usr/bin/env python3
"""Real Linux acceptance tests. Run as root on a disposable Linux host/VM."""
import argparse, hashlib, io, json, os, pathlib, subprocess, tarfile, tempfile, time

p = argparse.ArgumentParser()
p.add_argument('--binary', default='./bin/isolate')
p.add_argument('--probe', default='./bin/probe')
p.add_argument('--output', default='docs/integration-results.json')
a = p.parse_args()
binary = str(pathlib.Path(a.binary).resolve())
probe = pathlib.Path(a.probe).resolve()
assert os.geteuid() == 0, 'requires root on Linux'
base = pathlib.Path(tempfile.mkdtemp(prefix='isolate-integration-', dir='/var/tmp'))
root = base / 'store'
root.mkdir(mode=0o700)
cmd = [binary, '--root', str(root)]
results = []
completed = False
failure_detail = None

def call(*args, expect=0, timeout=30):
    r = subprocess.run(cmd + list(args), text=True, capture_output=True, timeout=timeout)
    assert r.returncode == expect, f'{args}: expected {expect}, got {r.returncode}\n{r.stdout}\n{r.stderr}'
    return r.stdout

def check(name, fn):
    start = time.monotonic()
    fn()
    results.append({'test': name, 'passed': True, 'seconds': round(time.monotonic()-start, 3)})
    print('PASS', name, flush=True)

def state(name): return json.loads(call('inspect', name))

def finished(name):
    for _ in range(150):
        s = state(name)
        if s['status'] in ('exited', 'failed'): return s
        time.sleep(.02)
    raise AssertionError('container did not finish: ' + name)

def run(name, mode, *options, expect=0):
    return call('run', '--name', name, *options, 'probe', '/probe', mode, expect=expect)

fs = base / 'rootfs'
fs.mkdir()
(fs / 'probe').write_bytes(probe.read_bytes())
(fs / 'probe').chmod(0o755)
(fs / 'shared').write_text('base\n')
(fs / 'stuff').mkdir()
(fs / 'stuff' / 'old').write_text('lower')
(fs / 'owned').mkdir(mode=0o700)
os.chown(fs / 'owned', 65534, 65534)
# A real shared file makes the storage comparison visible, without sparse files.
(fs / 'payload').write_bytes(b'X' * (8 << 20))
call('import', str(fs), 'probe')

try:
    def isolation():
        sentinel = base / 'host-sentinel'
        sentinel.write_text('host only')
        data = json.loads(run('isolation', 'inspect', '--env', 'HOST_SENTINEL='+str(sentinel)))
        assert data['uid'] == data['gid'] == 65534
        assert data['ppid'] == 1 and data['pid'] < 100
        assert data['interfaces'] == ['lo'] and data['root'] == '/'
        assert data['hostname'] == 'isolation' and data['host_hidden']
        assert all(data['security'].values()), data['security']
        assert not any(v.startswith('pipe:') for v in data['extra_fds'].values()), data['extra_fds']
        for ns, value in data['namespaces'].items():
            assert value != os.readlink('/proc/self/ns/' + ns), ns
        status = dict(line.split(':', 1) for line in data['status'].splitlines() if ':' in line)
        for key in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb']:
            assert int(status[key].strip(), 16) == 0, key
        assert status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2'
    check('PID/NET/MOUNT/UTS/IPC/cgroup namespaces and privilege restrictions', isolation)
    def root_restrictions():
        data = json.loads(run('root-user', 'inspect', '--uid','0','--gid','0'))
        assert data['uid'] == 0 and all(data['security'].values())
        assert 'CapEff:\t0000000000000000' in data['status']
    check('UID 0 still has no capabilities and cannot mount/unshare/mknod', root_restrictions)
    def exit_code():
        call('run','--name','exit-code','probe','/probe','exit','23',expect=23)
        assert state('exit-code')['exit_code'] == 23
    check('workload exit status preserved', exit_code)
    def cow():
        run('cow','write','--uid','0','--gid','0')
        assert (root/'containers/cow/upper/shared').read_text() == 'changed'
        m=json.loads(call('images'))[0]
        assert (root/'layers'/m['layers'][0]/'shared').read_text() == 'base\n'
        run('cow-second','ready')
        assert not (root/'containers/cow-second/upper/shared').exists()
    check('OverlayFS writes do not change base image or other instances',cow)
    def directory_ownership():
        assert call('run','--name','owned','probe','/probe','write-to','/owned/value').strip()=='owned'
        assert (root/'containers/owned/upper/owned/value').stat().st_uid==65534
    check('imported directory ownership permits designated non-root writes',directory_ownership)

    def cpu():
        run('cpu','cpu','--cpus','.25')
        s=state('cpu')['stats']
        assert s['throttled_periods'] > 0 and s['throttled_usec'] > 0, s
        assert 450_000 <= s['cpu_usage_usec'] <= 1_200_000, s
    check('CPU quota measured under sustained CPU load',cpu)
    def memory():
        run('memory','memory','--memory','32m',expect=137)
        s=state('memory')['stats']
        assert s['oom_kills'] >= 1, s
        assert s['memory_peak'] <= (32<<20) + (1<<20), s
    check('memory hard limit triggers a contained OOM kill',memory)
    def pids():
        text=run('pids','pids','--pids','32')
        assert 'limited after' in text, text
    check('pids.max bounds process/thread creation',pids)
    check('PID 1 reaps orphaned children',lambda: 'zombies=0' in run('orphan','orphan') or (_ for _ in ()).throw(AssertionError()))
    def signal_test():
        call('run','-d','--name','signal','probe','/probe','signal')
        for _ in range(100):
            if 'READY' in call('logs','signal'):break
            time.sleep(.01)
        call('stop','signal')
        assert finished('signal')['exit_code'] == 42
        assert 'TERM' in call('logs','signal')
    check('detached readiness, logs and graceful signal forwarding',signal_test)
    def forced():
        call('run','-d','--name','ignore','probe','/probe','ignore')
        time.sleep(.1)
        call('stop','--timeout','100ms','ignore')
        assert finished('ignore')['exit_code'] == 137
    check('stop escalates when workload ignores SIGTERM',forced)
    def failure():
        call('run','--name','missing','probe','/no-such-command',expect=125)
        s=state('missing')
        assert s['status']=='failed' and not pathlib.Path(s['cgroup']).exists()
    check('failed initialization cleans cgroup and reports failure',failure)
    def lifecycle():
        call('run','-d','--name','active','probe','/probe','sleep')
        call('rm','active',expect=125)
        call('run','--name','active','probe','/probe','ready',expect=125)
        call('stop','active')
        finished('active')
        call('rm','active')
        assert not (root/'containers/active').exists()
    check('active removal and duplicate names rejected; stopped removal succeeds',lifecycle)
    def malicious():
        for name,headers in {
            'traversal':[('../escaped', b'bad',None)],
            'symlink':[('escape',None,str(base)),('escape/escaped',b'bad',None)],
        }.items():
            archive=base/(name+'.tar')
            with tarfile.open(archive,'w') as t:
                for path,data,link in headers:
                    h=tarfile.TarInfo(path)
                    if link: h.type=tarfile.SYMTYPE;h.linkname=link;t.addfile(h)
                    else: h.size=len(data);t.addfile(h,io.BytesIO(data))
            call('import',str(archive),name,expect=125)
        assert not (base/'escaped').exists()
    check('malicious archive traversal and symlink escapes rejected',malicious)
    def mount_symlink():
        bad=base/'badroot';bad.mkdir();(bad/'proc').symlink_to('/tmp')
        call('import',str(bad),'badroot')
        call('run','--name','badmount','badroot','/probe','ready',expect=125)
        assert 'reserved mountpoint' in state('badmount')['error']
    check('image-controlled symlink mountpoints rejected before privilege drop',mount_symlink)
    def whiteouts():
        m=next(x for x in json.loads(call('images')) if x['name']=='probe')
        arc=base/'whiteout.tar'
        with tarfile.open(arc,'w') as t:
            h=tarfile.TarInfo('.wh.shared');h.size=0;t.addfile(h,io.BytesIO())
        top=json.loads(call('import',str(arc),'top'))
        top['layers']=m['layers']+top['layers']
        (root/'images/top.json').write_text(json.dumps(top))
        # Runtime still executes the probe from the lower layer.
        assert call('run','--name','whiteout','top','/probe','exists','/shared').strip() == 'absent'
        assert os.stat(root/'layers'/top['layers'][-1]/'shared').st_rdev == 0
    check('OCI whiteout layer mounts over a shared base',whiteouts)
    def opaque():
        m=next(x for x in json.loads(call('images')) if x['name']=='probe')
        arc=base/'opaque.tar'
        with tarfile.open(arc,'w') as t:
            for name,content in [('stuff/.wh..wh..opq',b''),('stuff/new',b'upper')]:
                h=tarfile.TarInfo(name);h.size=len(content);h.mode=0o644;t.addfile(h,io.BytesIO(content))
        top=json.loads(call('import',str(arc),'opaque'))
        top['layers']=m['layers']+top['layers']
        (root/'images/opaque.json').write_text(json.dumps(top))
        assert call('run','--name','opaque-old','opaque','/probe','exists','/stuff/old').strip()=='absent'
        assert call('run','--name','opaque-new','opaque','/probe','exists','/stuff/new').strip()=='present'
    check('OCI opaque directories hide lower children and preserve upper entries',opaque)
    def supervisor_death():
        proc=subprocess.Popen(cmd+['run','--name','supervisor-death','probe','/probe','sleep'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert proc.stdout.readline().strip()=='READY'
        for _ in range(100):
            s=state('supervisor-death')
            if s['status']=='running':break
            time.sleep(.01)
        proc.kill();proc.wait(timeout=5)
        for _ in range(150):
            tasks=pathlib.Path(s['cgroup'],'cgroup.procs').read_text().strip()
            if not tasks: break
            time.sleep(.02)
        assert not tasks, 'supervisor death left a workload running'
        call('rm','supervisor-death')
        assert not pathlib.Path(s['cgroup']).exists()
    check('supervisor death kills namespace workloads; rm recovers stale state',supervisor_death)
    def independent_stores():
        other_root=base/'other-store';other_root.mkdir(mode=0o700)
        other=[binary,'--root',str(other_root)]
        subprocess.run(other+['import',str(fs),'probe'],check=True,capture_output=True)
        call('run','-d','--name','same-name','probe','/probe','sleep')
        r=subprocess.run(other+['run','--name','same-name','probe','/probe','ready'],capture_output=True,text=True,timeout=10)
        assert r.returncode==0 and r.stdout.strip()=='READY', r.stderr
        call('stop','same-name');finished('same-name');call('rm','same-name')
        subprocess.run(other+['rm','same-name'],check=True,capture_output=True)
    check('independent stores can use the same container name concurrently',independent_stores)


    def cleanup():
        for s in json.loads(call('ps')):
            assert not pathlib.Path(s['cgroup']).exists() if s['cgroup'] else True
            call('rm',s['spec']['id'])
        assert json.loads(call('ps')) == []
        assert not list((root/'containers').iterdir())
        assert not any(str(root) in line for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines())
    check('all containers clean up without host mount or cgroup leaks',cleanup)
    completed = True
except Exception as e:
    failure_detail = str(e)
    raise
finally:
    # Try to stop any test workloads even when an assertion fails. Keep files for diagnosis.
    for s in json.loads(call('ps')):
        if s['status']=='running':
            subprocess.run(cmd+['stop','--timeout','100ms',s['spec']['id']],capture_output=True)
    report={'all_passed':completed,'failure':failure_detail,'binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),'probe_sha256':hashlib.sha256(probe.read_bytes()).hexdigest(),'kernel':os.uname().release,'architecture':os.uname().machine,'test_directory':str(base),'passed':len(results),'tests':results}
    out=pathlib.Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
    print('Report:',out)
