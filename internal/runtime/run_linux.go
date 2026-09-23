package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dhruv/isolate/internal/cgroup"
	"github.com/dhruv/isolate/internal/config"
	"github.com/dhruv/isolate/internal/image"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Options struct {
	CgroupParent   string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Ready          func(State) error
}

func resolve(spec config.Spec, m image.Manifest) (config.Spec, error) {
	args := spec.Args
	if len(args) == 0 {
		args = m.Cmd
	}
	spec.Args = append(append([]string{}, m.Entrypoint...), args...)
	if len(spec.Args) == 0 {
		return spec, fmt.Errorf("no command supplied and image has no default command")
	}
	env := map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/tmp", "HOSTNAME": spec.ID}
	for _, list := range [][]string{m.Env, spec.Env} {
		for _, e := range list {
			k, v, ok := strings.Cut(e, "=")
			if !ok || k == "" || strings.IndexByte(e, 0) >= 0 {
				return spec, fmt.Errorf("invalid image environment")
			}
			env[k] = v
		}
	}
	spec.Env = nil
	keys := []string{}
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		spec.Env = append(spec.Env, k+"="+env[k])
	}
	if spec.Workdir == "" {
		spec.Workdir = m.Workdir
	}
	if spec.Workdir == "" {
		spec.Workdir = "/"
	}
	return spec, spec.Validate()
}
func Run(ctx context.Context, store *image.Store, spec config.Spec, opt Options) (code int, retErr error) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread() // Pdeathsig is tied to the creating thread.
	began := time.Now()
	code = 125
	if os.Geteuid() != 0 {
		return code, fmt.Errorf("run requires root on Linux")
	}
	if err := spec.Validate(); err != nil {
		return code, err
	}
	m, err := store.Load(spec.Image)
	if err != nil {
		return code, err
	}
	spec, err = resolve(spec, m)
	if err != nil {
		return code, err
	}
	if opt.CgroupParent == "" {
		opt.CgroupParent = "/sys/fs/cgroup"
	}
	if err = cgroup.Prepare(opt.CgroupParent); err != nil {
		return code, err
	}
	dir := filepath.Join(store.Root, "containers", spec.ID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return code, fmt.Errorf("reserve container: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return code, err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return code, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	st := State{Spec: spec, Status: "creating", Created: began, ExitCode: 125}
	defer func() {
		now := time.Now()
		st.Finished = &now
		st.ExitCode = code
		st.Status = "exited"
		if retErr != nil {
			st.Status = "failed"
			st.Error = retErr.Error()
		}
		if e := save(store, st); e != nil {
			retErr = errors.Join(retErr, e)
		}
	}()
	if err = save(store, st); err != nil {
		return code, err
	}
	for _, p := range []string{"upper", "work", "merged"} {
		mode := os.FileMode(0700)
		if p == "upper" {
			mode = 0755
		}
		if err = os.Mkdir(filepath.Join(dir, p), mode); err != nil {
			return code, err
		}
	}
	// Namespace cgroup names by store as well as ID. Independent stores can run
	// identical container names without collisions in the shared kernel tree.
	groupKey := fmt.Sprintf("%x", sha256.Sum256([]byte(store.Root+"\x00"+spec.ID)))
	group, err := cgroup.Create(opt.CgroupParent, groupKey, spec.Limits)
	if err != nil {
		return code, err
	}
	st.Cgroup = group.Path
	defer func() {
		if e := group.Kill(); e != nil {
			retErr = errors.Join(retErr, e)
		}
		st.Stats = cgroup.ReadStats(group.Path)
		if e := group.Close(); e != nil {
			retErr = errors.Join(retErr, e)
		}
	}()
	cr, cw, err := os.Pipe()
	if err != nil {
		return code, err
	}
	defer cr.Close()
	defer cw.Close()
	rr, rw, err := os.Pipe()
	if err != nil {
		return code, err
	}
	defer rr.Close()
	defer rw.Close()
	aliveR, aliveW, err := os.Pipe()
	if err != nil {
		return code, err
	}
	defer aliveR.Close()
	defer aliveW.Close()
	exe, err := os.Executable()
	if err != nil {
		return code, err
	}
	cmd := exec.Command(exe, "_init")
	cmd.Env = []string{"GOMAXPROCS=1"}
	cmd.Stdin = opt.Stdin
	cmd.Stdout = opt.Stdout
	cmd.Stderr = opt.Stderr
	cmd.ExtraFiles = []*os.File{cr, rw, aliveR}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWCGROUP, UseCgroupFD: true, CgroupFD: int(group.File.Fd()), Pdeathsig: syscall.SIGKILL}
	if err = cmd.Start(); err != nil {
		return code, fmt.Errorf("clone namespaces/cgroup (Linux >=5.14 required): %w", err)
	}
	cr.Close()
	rw.Close()
	aliveR.Close()
	waited := false
	defer func() {
		if !waited {
			_ = group.Kill()
			_ = cmd.Wait()
		}
	}()
	st.PID = cmd.Process.Pid
	st.StartTicks, err = startTicks(st.PID)
	if err != nil {
		return code, err
	}
	if err = json.NewEncoder(cw).Encode(initConfig{Spec: spec, Lower: store.LayerPaths(m), Dir: dir}); err != nil {
		return code, err
	}
	cw.Close()
	readiness := make(chan error, 1)
	go func() {
		var msg readyMessage
		e := json.NewDecoder(rr).Decode(&msg)
		if e == nil && msg.Error != "" {
			e = errors.New(msg.Error)
		}
		readiness <- e
	}()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case err = <-readiness:
		if err != nil {
			return code, fmt.Errorf("initialize: %w", err)
		}
	case <-ctx.Done():
		return code, ctx.Err()
	case <-timer.C:
		return code, fmt.Errorf("initialization timed out")
	}
	st.StartupMS = float64(time.Since(began).Nanoseconds()) / 1e6
	st.Status = "running"
	if err = save(store, st); err != nil {
		return code, err
	}
	if opt.Ready != nil {
		if err = opt.Ready(st); err != nil {
			return code, err
		}
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case sig := <-sigs:
			_ = cmd.Process.Signal(sig)
		case <-ctx.Done():
			_ = group.Kill()
			<-done
			waited = true
			return 125, ctx.Err()
		case err = <-done:
			waited = true
			if err == nil {
				return 0, nil
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				status := ee.Sys().(syscall.WaitStatus)
				if status.Signaled() {
					return 128 + int(status.Signal()), nil
				}
				return ee.ExitCode(), nil
			}
			return 125, err
		}
	}
}
