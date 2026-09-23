#!/usr/bin/env python3
"""Measure warm startup, 50+ concurrent services and allocated storage sharing.

Thresholds are explicit acceptance targets, never pre-populated results. Registry
pulls, cold caches, application initialization and disk-full behavior are separate.
"""
import argparse, concurrent.futures, hashlib, json, math, os, pathlib, platform, select, statistics, subprocess, tempfile, time
p=argparse.ArgumentParser()
p.add_argument('--binary',default='./bin/isolate')
p.add_argument('--probe',default='./bin/probe')
p.add_argument('--samples',type=int,default=100)
p.add_argument('--concurrency',type=int,default=50)
p.add_argument('--rounds',type=int,default=20)
p.add_argument('--output',default='docs/benchmark-results.json')
p.add_argument('--enforce',action='store_true',help='fail if measured targets are not met')
a=p.parse_args()
assert os.geteuid()==0 and a.samples>=10 and a.concurrency>=1 and a.rounds>=5
base=pathlib.Path(tempfile.mkdtemp(prefix='isolate-benchmark-',dir='/var/tmp'))
root=base/'store';root.mkdir(mode=0o700)
cmd=[str(pathlib.Path(a.binary).resolve()),'--root',str(root)]

def call(*args):
    r=subprocess.run(cmd+list(args),capture_output=True,text=True,timeout=30)
    if r.returncode: raise RuntimeError(f'{args}: {r.returncode}: {r.stderr}')
    return r.stdout

def summary(xs):
    ys=sorted(xs)
    return {'count':len(ys),'min':ys[0],'median':statistics.median(ys),'p95':ys[math.ceil(len(ys)*.95)-1], 'p99':ys[math.ceil(len(ys)*.99)-1],'max':ys[-1]}

def allocated(path):
    # st_blocks counts real allocation, including directory metadata. No du -b,
    # sparse-file sizes, compression ratios or assumed 80% savings.
    seen=set();total=0
    for directory,dirs,files in os.walk(path):
        for item in [pathlib.Path(directory)]+[pathlib.Path(directory)/f for f in files]:
            st=item.lstat();key=(st.st_dev,st.st_ino)
            if key not in seen: total+=st.st_blocks*512;seen.add(key)
    return total

fs=base/'rootfs';fs.mkdir()
(fs/'probe').write_bytes(pathlib.Path(a.probe).read_bytes());(fs/'probe').chmod(0o755)
with (fs/'payload').open('wb') as f:
    block=bytes(range(256))*4096
    for _ in range(16):f.write(block)
call('import',str(fs),'probe')
services=[]

def launch(i):
    proc=subprocess.Popen(cmd+['run','--name',f'svc-{i}','--cpus','.25','probe','/probe','service'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    services.append(proc)
    if not select.select([proc.stdout],[],[],30)[0] or proc.stdout.readline().strip()!='READY':
        proc.kill();raise RuntimeError('service did not become ready')
    return proc

def ping(proc):
    start=time.perf_counter_ns();proc.stdin.write('ping\n');proc.stdin.flush()
    if not select.select([proc.stdout],[],[],5)[0]:raise RuntimeError('request timed out')
    if proc.stdout.readline().strip()!='OK':raise RuntimeError('invalid response')
    return (time.perf_counter_ns()-start)/1e6

report={}
try:
    for i in range(5):
        call('run','--name',f'warm-{i}','probe','/probe','ready');call('rm',f'warm-{i}')
    startup=[];wall=[]
    for i in range(a.samples):
        start=time.perf_counter_ns()
        text=call('run','--name',f'start-{i}','probe','/probe','ready')
        wall.append((time.perf_counter_ns()-start)/1e6)
        assert text.strip()=='READY'
        startup.append(json.loads(call('inspect',f'start-{i}'))['startup_ms'])
        call('rm',f'start-{i}')
    print('Warm startup:',summary(startup),flush=True)
    one=launch(0)
    baseline=[]
    for _ in range(a.rounds):
        baseline.append(ping(one));time.sleep(.02)
    # Keep all services alive concurrently, with one independent writable layer
    # and cgroup per service. 50 .25-core ceilings are not a CPU reservation.
    start=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16,a.concurrency)) as pool:
        others=list(pool.map(launch,range(1,a.concurrency)))
    procs=[one]+others
    ready_seconds=time.monotonic()-start
    latencies=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as pool:
        for _ in range(a.rounds):
            latencies.extend(pool.map(ping,procs));time.sleep(.02)
    states=json.loads(call('ps'))
    assert sum(s['status']=='running' for s in states)==a.concurrency
    shared=allocated(root/'layers')
    writable=sum(allocated(root/'containers'/f'svc-{i}'/'upper')+allocated(root/'containers'/f'svc-{i}'/'work') for i in range(a.concurrency))
    actual=shared+writable
    full_copy=a.concurrency*shared+writable
    reduction=100*(1-actual/full_copy)
    latency=summary(latencies)
    checks={'warm_startup_p95_under_100ms':summary(startup)['p95']<100,
            'warm_cli_to_exit_p95_under_100ms':summary(wall)['p95']<100,
            'at_least_50_simultaneous_workloads':a.concurrency>=50,
            'concurrent_request_p95_under_50ms':latency['p95']<50,
            'all_requests_succeeded':len(latencies)==a.concurrency*a.rounds,
            'allocated_storage_reduction_at_least_80_percent':reduction>=80}
    report={'binary_sha256':hashlib.sha256(pathlib.Path(a.binary).read_bytes()).hexdigest(),'probe_sha256':hashlib.sha256(pathlib.Path(a.probe).read_bytes()).hexdigest(),'measured_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'environment':{'kernel':platform.release(),'architecture':platform.machine(),'logical_cpus':os.cpu_count(),'memory_info':pathlib.Path('/proc/meminfo').read_text().splitlines()[:3]},
        'method':{'startup':'warm runtime entry through successful workload exec acknowledgement; 5 warmups; imports excluded','cli_wall':'process launch through READY output, workload exit and runtime cleanup','concurrency':'separate loopback-only containers; 16 SHA-256 hashes of 4 KiB per request, .25 CPU/64 MiB cap per container; 20ms pause between bursts','storage':'st_blocks*512; shared lower plus per-instance upper/work vs N copies of same lower plus upper/work; tmpfs and image downloads excluded'},
        'startup_ms':summary(startup),'cli_wall_ms':summary(wall),'startup_samples_ms':startup,'cli_wall_samples_ms':wall,
        'concurrency':{'workloads':a.concurrency,'rounds':a.rounds,'successful_requests':len(latencies),'additional_launch_seconds':ready_seconds,'single_service_latency_ms':summary(baseline),'concurrent_latency_ms':latency,'p95_ratio_to_single_service':latency['p95']/summary(baseline)['p95']},
        'storage':{'shared_lower_allocated_bytes':shared,'all_upper_and_work_allocated_bytes':writable,'actual_allocated_bytes':actual,'full_copy_comparison_bytes':full_copy,'reduction_percent':reduction},
        'targets':checks,'all_targets_met':all(checks.values()),'test_directory':str(base)}
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('samples_ms')},indent=2),flush=True)
finally:
    for proc in services:
        if proc.poll() is None:
            try:proc.stdin.close()
            except BrokenPipeError:pass
    for proc in services:
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    if report:
        # Retain layer/state evidence and include cleanup verification.
        final=json.loads(call('ps'))
        report['cleanup_verified']=all(s['status']=='exited' and not pathlib.Path(s['cgroup']).exists() for s in final)
        out=pathlib.Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
if a.enforce and (not report.get('all_targets_met') or not report.get('cleanup_verified')):raise SystemExit(1)
