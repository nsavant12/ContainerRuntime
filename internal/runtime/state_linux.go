// Package runtime implements the Linux container lifecycle without Docker or runc.
package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dhruv/isolate/internal/cgroup"
	"github.com/dhruv/isolate/internal/config"
	"github.com/dhruv/isolate/internal/image"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type State struct {
	Spec       config.Spec  `json:"spec"`
	Status     string       `json:"status"`
	PID        int          `json:"pid"`
	StartTicks string       `json:"start_ticks"`
	Created    time.Time    `json:"created"`
	Finished   *time.Time   `json:"finished,omitempty"`
	StartupMS  float64      `json:"startup_ms"`
	ExitCode   int          `json:"exit_code"`
	Error      string       `json:"error,omitempty"`
	Cgroup     string       `json:"cgroup"`
	Stats      cgroup.Stats `json:"stats"`
}

func statePath(s *image.Store, id string) string {
	return filepath.Join(s.Root, "containers", id, "state.json")
}
func Load(s *image.Store, id string) (State, error) {
	var st State
	if err := config.Name(id); err != nil {
		return st, err
	}
	b, err := os.ReadFile(statePath(s, id))
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}
func List(s *image.Store) ([]State, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "containers"))
	if err != nil {
		return nil, err
	}
	states := []State{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := Load(s, e.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		states = append(states, st)
	}
	return states, nil
}
func save(s *image.Store, st State) error { return image.AtomicJSON(statePath(s, st.Spec.ID), st) }
func startTicks(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return "", fmt.Errorf("invalid proc stat")
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) < 20 {
		return "", fmt.Errorf("short proc stat")
	}
	return fields[19], nil
}
func liveFD(st State) (int, error) {
	fd, err := unix.PidfdOpen(st.PID, 0)
	if err != nil {
		return -1, err
	}
	ticks, err := startTicks(st.PID)
	if err != nil || ticks != st.StartTicks {
		unix.Close(fd)
		return -1, fmt.Errorf("container process no longer exists")
	}
	return fd, nil
}
func Stop(s *image.Store, id string, timeout time.Duration) error {
	st, err := Load(s, id)
	if err != nil {
		return err
	}
	if st.Status != "running" {
		return nil
	}
	fd, err := liveFD(st)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 50)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if n > 0 {
			return nil
		}
	}
	err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}
func Remove(s *image.Store, id string) error {
	if err := config.Name(id); err != nil {
		return err
	}
	dir := filepath.Join(s.Root, "containers", id)
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("container %s is active; stop it first", id)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	st, err := Load(s, id)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if st.Status == "running" {
		if fd, e := liveFD(st); e == nil {
			unix.Close(fd)
			return fmt.Errorf("container init is still alive")
		}
	}
	// A killed supervisor may leave an empty cgroup. Only remove it after proving
	// there are no tasks, never kill by an unverified stale PID.
	if st.Cgroup != "" {
		if b, e := os.ReadFile(filepath.Join(st.Cgroup, "cgroup.procs")); e == nil {
			if strings.TrimSpace(string(b)) != "" {
				return fmt.Errorf("cgroup still has processes")
			}
			if e = os.Remove(st.Cgroup); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if err = os.RemoveAll(dir); err != nil {
		return err
	}
	err = os.Remove(filepath.Join(s.Root, "logs", id+".log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func Stats(s *image.Store, id string) (State, error) {
	st, err := Load(s, id)
	if err != nil {
		return st, err
	}
	if st.Status == "running" {
		st.Stats = cgroup.ReadStats(st.Cgroup)
	}
	return st, nil
}
func pidString(pid int) string { return strconv.Itoa(pid) }
