package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dhruv/isolate/internal/config"
	"github.com/dhruv/isolate/internal/security"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"syscall"
)

type initConfig struct {
	Spec  config.Spec
	Lower []string
	Dir   string
}
type readyMessage struct {
	Error string `json:"error,omitempty"`
}

// Init is a private re-exec entrypoint. Only the PID 1 namespace child may use it.
func Init() int {
	goruntime.LockOSThread()
	// ExtraFiles deliberately arrive without CLOEXEC. Keep the readiness channel
	// in init, never in the untrusted workload or its descendants.
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	unix.CloseOnExec(5)
	ready := os.NewFile(4, "ready")
	if ready == nil {
		return 125
	}
	defer ready.Close()
	fail := func(err error) int {
		json.NewEncoder(ready).Encode(readyMessage{Error: err.Error()})
		fmt.Fprintln(os.Stderr, "isolate init:", err)
		return 125
	}
	if os.Getpid() != 1 {
		return fail(fmt.Errorf("internal init must be PID 1"))
	}
	// setuid/setgid clear PR_SET_PDEATHSIG. A pipe whose only writer is the
	// supervisor covers that credential-change window, including parent death
	// before init has even started. No liveness FD reaches application exec.
	alive := os.NewFile(5, "supervisor-liveness")
	if alive == nil {
		return fail(fmt.Errorf("missing supervisor liveness pipe"))
	}
	go func() {
		var b [1]byte
		_, _ = alive.Read(b[:])
		os.Exit(137)
	}()
	pipe := os.NewFile(3, "config")
	if pipe == nil {
		return fail(fmt.Errorf("missing configuration"))
	}
	var cfg initConfig
	err := json.NewDecoder(io.LimitReader(pipe, 1<<20)).Decode(&cfg)
	pipe.Close()
	if err != nil {
		return fail(err)
	}
	if err = mountRoot(cfg); err != nil {
		return fail(err)
	}
	if err = security.Apply(cfg.Spec.UID, cfg.Spec.GID); err != nil {
		return fail(fmt.Errorf("security: %w", err))
	}
	if err = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fail(err)
	}
	if err = os.Chdir(cfg.Spec.Workdir); err != nil {
		return fail(err)
	}
	os.Clearenv()
	for _, e := range cfg.Spec.Env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				os.Setenv(e[:i], e[i+1:])
				break
			}
		}
	}
	// Register handlers before starting the workload. PID 1 must explicitly handle
	// signals; otherwise the kernel gives namespace init special immunity.
	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	cmd := exec.Command(cfg.Spec.Args[0], cfg.Spec.Args[1:]...)
	cmd.Env = cfg.Spec.Env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		return fail(err)
	}
	go func() {
		for s := range sigs {
			_ = unix.Kill(-cmd.Process.Pid, s.(syscall.Signal))
		}
	}()
	if err = json.NewEncoder(ready).Encode(readyMessage{}); err != nil {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		return 125
	}
	ready.Close()
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 125
		}
		if pid == cmd.Process.Pid {
			if status.Signaled() {
				return 128 + int(status.Signal())
			}
			return status.ExitStatus()
		}
	}
}
func ensureDir(root, p string, mode os.FileMode) error {
	full := filepath.Join(root, p)
	st, err := os.Lstat(full)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(full, mode)
	}
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("reserved mountpoint %s must be a real directory", p)
	}
	return nil
}
func mountRoot(c initConfig) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	merged := filepath.Join(c.Dir, "merged")
	opts := "lowerdir="
	for i, p := range c.Lower {
		if i > 0 {
			opts += ":"
		}
		opts += p
	}
	opts += ",upperdir=" + filepath.Join(c.Dir, "upper") + ",workdir=" + filepath.Join(c.Dir, "work")
	if len(opts) > os.Getpagesize()-1 {
		return fmt.Errorf("overlay mount options exceed page size")
	}
	if err := unix.Mount("overlay", merged, "overlay", unix.MS_NOSUID|unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("overlay: %w", err)
	}
	for _, p := range []string{"proc", "dev", "tmp", "sys"} {
		if err := ensureDir(merged, p, 0755); err != nil {
			return err
		}
	}
	old := filepath.Join(merged, ".isolate-old")
	if err := os.Mkdir(old, 0700); err != nil {
		return err
	}
	if err := unix.PivotRoot(merged, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/.isolate-old", unix.MNT_DETACH); err != nil {
		return err
	}
	if err := os.Remove("/.isolate-old"); err != nil {
		return err
	}
	if err := unix.Sethostname([]byte(c.Spec.ID)); err != nil {
		return err
	}
	if err := loopback(); err != nil {
		return err
	}
	safe := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("proc", "/proc", "proc", safe, ""); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/dev", "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=755,size=4m"); err != nil {
		return err
	}
	for _, d := range []struct {
		name  string
		minor uint32
	}{{"null", 3}, {"zero", 5}, {"full", 7}, {"random", 8}, {"urandom", 9}} {
		if err := unix.Mknod("/dev/"+d.name, unix.S_IFCHR|0666, int(unix.Mkdev(1, d.minor))); err != nil {
			return err
		}
		if err := os.Chmod("/dev/"+d.name, 0666); err != nil {
			return err
		}
	}
	for _, p := range [][2]string{{"/proc/self/fd", "/dev/fd"}, {"/proc/self/fd/0", "/dev/stdin"}, {"/proc/self/fd/1", "/dev/stdout"}, {"/proc/self/fd/2", "/dev/stderr"}} {
		if err := os.Symlink(p[0], p[1]); err != nil {
			return err
		}
	}
	if err := os.Mkdir("/dev/shm", 01777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/dev/shm", "tmpfs", safe, "mode=1777,size=64m"); err != nil {
		return err
	}
	for _, p := range []string{"/proc/sys", "/proc/irq", "/proc/bus", "/proc/fs"} {
		if _, err := os.Stat(p); err == nil {
			if err = unix.Mount("tmpfs", p, "tmpfs", safe|unix.MS_RDONLY, "size=4k"); err != nil {
				return err
			}
		}
	}
	for _, p := range []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sysrq-trigger", "/proc/latency_stats", "/proc/sched_debug"} {
		if _, err := os.Stat(p); err == nil {
			if err = unix.Mount("/dev/null", p, "", unix.MS_BIND, ""); err != nil {
				return err
			}
			if err = unix.Mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil {
				return err
			}
		}
	}
	if err := unix.Mount("", "/proc", "", safe|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", "/sys", "tmpfs", safe|unix.MS_RDONLY, "size=4k,mode=755"); err != nil {
		return err
	}
	return unix.Mount("tmpfs", "/tmp", "tmpfs", safe, "size=64m,mode=1777")
}
func loopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	req, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	req.SetUint16(unix.IFF_UP | unix.IFF_LOOPBACK | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, req)
}
