package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/dhruv/isolate/internal/cgroup"
	"github.com/dhruv/isolate/internal/config"
	"github.com/dhruv/isolate/internal/image"
	rt "github.com/dhruv/isolate/internal/runtime"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const usage = `isolate — a small Linux container runtime

Usage: isolate [--root /var/lib/isolate] COMMAND [OPTIONS]

  pull REFERENCE NAME           Pull a linux image from an OCI/Docker registry
  import ROOTFS_OR_TAR NAME      Import a local rootfs or uncompressed tar
  images                        List local images as JSON
  run [OPTIONS] IMAGE [COMMAND [ARG...]]
  ps                            List containers as JSON
  inspect ID                    Configuration, lifecycle and live/final statistics
  stats ID                      Resource statistics as JSON
  stop [--timeout 5s] ID         SIGTERM, then SIGKILL after timeout
  logs ID                       Print detached container output
  rm ID                         Remove stopped container and writable layer
  doctor                        Check kernel features and cgroup controllers

Run options (must precede IMAGE):
  --name NAME      Container identifier (default: random)
  --cpus 1         CPU quota in cores (0.01–1024)
  --memory 64m     Memory cap; swap disabled
  --pids 64        Maximum processes/threads, including init
  --uid 65534      Workload user (all capabilities dropped even for UID 0)
  --gid 65534      Workload group
  --workdir /     Override image working directory
  --env KEY=VALUE  Add environment variable (repeatable)
  -d              Detach; return only after successful workload exec
  --cgroup-parent /sys/fs/cgroup  Prepared cgroup v2 parent

Network: private namespace with loopback only. No host networking or ports.
Exit codes: workload exit code, 128+signal, or 125 for runtime failure.
`

type envFlags []string

func (e *envFlags) String() string     { return strings.Join(*e, ",") }
func (e *envFlags) Set(v string) error { *e = append(*e, v); return nil }
func output(v any) error               { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); return e.Encode(v) }
func runCLI(args []string) (int, error) {
	if len(args) > 0 && args[0] == "_init" {
		return rt.Init(), nil
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(usage)
		return 0, nil
	}
	global := flag.NewFlagSet("isolate", flag.ContinueOnError)
	root := global.String("root", "/var/lib/isolate", "private state and image directory")
	if err := global.Parse(args); err != nil {
		return 125, err
	}
	args = global.Args()
	if len(args) == 0 {
		return 125, errors.New("command required")
	}
	if args[0] == "doctor" {
		return doctor()
	}
	if os.Geteuid() != 0 {
		return 125, errors.New("isolate requires root; use sudo on a Linux host or VM")
	}
	s, err := image.New(*root)
	if err != nil {
		return 125, err
	}
	need := func(n int) error {
		if len(args) != n {
			return fmt.Errorf("incorrect arguments for %s; see isolate help", args[0])
		}
		return nil
	}
	switch args[0] {
	case "pull":
		if err = need(3); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			var m image.Manifest
			m, err = s.Pull(ctx, args[1], args[2])
			if err == nil {
				err = output(m)
			}
		}
	case "import":
		if err = need(3); err == nil {
			var m image.Manifest
			m, err = s.Import(args[1], args[2])
			if err == nil {
				err = output(m)
			}
		}
	case "images":
		if err = need(1); err == nil {
			var m []image.Manifest
			m, err = s.List()
			if err == nil {
				err = output(m)
			}
		}
	case "run", "_monitor":
		return runContainer(s, args[1:], args[0] == "_monitor")
	case "ps":
		if err = need(1); err == nil {
			var st []rt.State
			st, err = rt.List(s)
			if err == nil {
				err = output(st)
			}
		}
	case "inspect", "stats":
		if err = need(2); err == nil {
			var st rt.State
			st, err = rt.Stats(s, args[1])
			if err == nil {
				if args[0] == "stats" {
					err = output(st.Stats)
				} else {
					err = output(st)
				}
			}
		}
	case "stop":
		f := flag.NewFlagSet("stop", flag.ContinueOnError)
		timeout := f.Duration("timeout", 5*time.Second, "grace period")
		if err = f.Parse(args[1:]); err == nil {
			if f.NArg() != 1 || *timeout < 0 || *timeout > time.Hour {
				err = errors.New("stop expects a name and timeout between 0 and 1h")
			} else {
				err = rt.Stop(s, f.Arg(0), *timeout)
			}
		}
	case "rm":
		if err = need(2); err == nil {
			err = rt.Remove(s, args[1])
		}
	case "logs":
		if err = need(2); err == nil {
			if err = config.Name(args[1]); err == nil {
				var f *os.File
				f, err = os.Open(filepath.Join(s.Root, "logs", args[1]+".log"))
				if err == nil {
					defer f.Close()
					_, err = io.Copy(os.Stdout, f)
				}
			}
		}
	default:
		err = fmt.Errorf("unknown command %q; see isolate help", args[0])
	}
	if err != nil {
		return 125, err
	}
	return 0, nil
}
func runContainer(s *image.Store, args []string, monitor bool) (int, error) {
	f := flag.NewFlagSet("run", flag.ContinueOnError)
	id := f.String("name", "", "container name")
	cpus := f.Float64("cpus", 1, "CPU cores")
	mem := f.String("memory", "64m", "memory cap")
	pids := f.Int64("pids", 64, "process limit")
	uid := f.Int("uid", 65534, "user ID")
	gid := f.Int("gid", 65534, "group ID")
	wd := f.String("workdir", "", "workdir")
	detach := f.Bool("d", false, "detach")
	parent := f.String("cgroup-parent", "/sys/fs/cgroup", "cgroup v2 parent")
	var env envFlags
	f.Var(&env, "env", "KEY=VALUE")
	if err := f.Parse(args); err != nil {
		return 125, err
	}
	if f.NArg() < 1 {
		return 125, errors.New("run requires an image")
	}
	if *id == "" {
		*id = config.ID()
	}
	memory, err := config.Bytes(*mem)
	if err != nil {
		return 125, err
	}
	spec := config.Spec{ID: *id, Image: f.Arg(0), Args: f.Args()[1:], Env: env, Workdir: *wd, UID: *uid, GID: *gid, Limits: config.Limits{CPUs: *cpus, Memory: memory, Pids: *pids}}
	if err = spec.Validate(); err != nil {
		return 125, err
	}
	if *detach && !monitor {
		return detached(s, spec, *parent)
	}
	opt := rt.Options{CgroupParent: *parent, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	var ack *os.File
	if monitor {
		ack = os.NewFile(3, "detach-ready")
		defer ack.Close()
		opt.Ready = func(st rt.State) error {
			err := json.NewEncoder(ack).Encode(map[string]string{"id": st.Spec.ID})
			ack.Close()
			return err
		}
	}
	code, err := rt.Run(context.Background(), s, spec, opt)
	if monitor && err != nil {
		_ = json.NewEncoder(ack).Encode(map[string]string{"error": err.Error()})
	}
	return code, err
}
func detached(s *image.Store, spec config.Spec, parent string) (int, error) {
	// Reserve logs exclusively so duplicate names cannot truncate existing output.
	log, err := os.OpenFile(filepath.Join(s.Root, "logs", spec.ID+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 125, err
	}
	defer log.Close()
	r, w, err := os.Pipe()
	if err != nil {
		return 125, err
	}
	defer r.Close()
	defer w.Close()
	exe, err := os.Executable()
	if err != nil {
		return 125, err
	}
	args := []string{"--root", s.Root, "_monitor", "--name", spec.ID, "--cpus", fmt.Sprint(spec.Limits.CPUs), "--memory", fmt.Sprint(spec.Limits.Memory), "--pids", fmt.Sprint(spec.Limits.Pids), "--uid", fmt.Sprint(spec.UID), "--gid", fmt.Sprint(spec.GID), "--cgroup-parent", parent}
	if spec.Workdir != "" {
		args = append(args, "--workdir", spec.Workdir)
	}
	for _, e := range spec.Env {
		args = append(args, "--env", e)
	}
	args = append(args, spec.Image)
	args = append(args, spec.Args...)
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{"GOMAXPROCS=1", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return 125, err
	}
	w.Close()
	var msg map[string]string
	err = json.NewDecoder(r).Decode(&msg)
	if err != nil || msg["error"] != "" {
		_ = cmd.Wait()
		if msg["error"] != "" {
			err = errors.New(msg["error"])
		}
		return 125, err
	}
	if msg["id"] != spec.ID {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 125, errors.New("invalid monitor acknowledgement")
	}
	_ = cmd.Process.Release()
	fmt.Println(spec.ID)
	return 0, nil
}
func doctor() (int, error) {
	b, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return 125, err
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return 125, err
	}
	version, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	report := map[string]any{"kernel": strings.TrimSpace(string(version)), "root": os.Geteuid() == 0, "overlayfs": strings.Contains(string(b), "overlay"), "cgroup_v2_controllers": strings.Fields(string(controllers)), "required": "Linux >=5.14; cgroup v2 cpu,memory,pids; OverlayFS; seccomp; amd64/arm64"}
	if err = output(report); err != nil {
		return 125, err
	}
	if !report["overlayfs"].(bool) {
		return 125, errors.New("OverlayFS unavailable; try modprobe overlay")
	}
	if os.Geteuid() == 0 {
		if err = cgroup.Prepare("/sys/fs/cgroup"); err != nil {
			return 125, err
		}
	}
	return 0, nil
}
