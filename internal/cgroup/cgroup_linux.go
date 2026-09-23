// Package cgroup manages cgroup v2 CPU, memory and process budgets.
package cgroup

import (
	"errors"
	"fmt"
	"github.com/dhruv/isolate/internal/config"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Group struct {
	Path string
	File *os.File
}
type Stats struct {
	CPUUsageUsec     uint64 `json:"cpu_usage_usec"`
	ThrottledUsec    uint64 `json:"throttled_usec"`
	ThrottledPeriods uint64 `json:"throttled_periods"`
	MemoryCurrent    uint64 `json:"memory_current"`
	MemoryPeak       uint64 `json:"memory_peak"`
	OOMKills         uint64 `json:"oom_kills"`
	PidsCurrent      uint64 `json:"pids_current"`
}

func write(p, n, v string) error {
	if err := os.WriteFile(filepath.Join(p, n), []byte(v), 0600); err != nil {
		return fmt.Errorf("cgroup %s: %w", n, err)
	}
	return nil
}
func Prepare(parent string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(parent, &st); err != nil {
		return err
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not cgroup v2", parent)
	}
	b, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return err
	}
	available := " " + strings.TrimSpace(string(b)) + " "
	for _, c := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(available, " "+c+" ") {
			return fmt.Errorf("controller %s unavailable at %s", c, parent)
		}
	}
	return write(parent, "cgroup.subtree_control", "+cpu +memory +pids")
}
func Create(parent, id string, l config.Limits) (*Group, error) {
	if err := config.Name(id); err != nil {
		return nil, err
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	p := filepath.Join(parent, "isolate-"+id)
	if err := os.Mkdir(p, 0755); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(p)
		}
	}()
	for _, v := range [][2]string{{"cpu.max", l.CPUMax()}, {"memory.max", strconv.FormatInt(l.Memory, 10)}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"pids.max", strconv.FormatInt(l.Pids, 10)}} {
		if err := write(p, v[0], v[1]); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(filepath.Join(p, "cgroup.kill")); err != nil {
		return nil, fmt.Errorf("Linux >=5.14 with cgroup.kill required: %w", err)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	ok = true
	return &Group{p, f}, nil
}
func (g *Group) Kill() error { return write(g.Path, "cgroup.kill", "1") }
func (g *Group) Close() error {
	if g.File != nil {
		g.File.Close()
		g.File = nil
	}
	for i := 0; i < 100; i++ {
		err := os.Remove(g.Path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("cgroup still busy: %s", g.Path)
}
func readNum(p, n string) uint64 {
	b, _ := os.ReadFile(filepath.Join(p, n))
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}
func readKV(p, n string) map[string]uint64 {
	b, _ := os.ReadFile(filepath.Join(p, n))
	out := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			out[f[0]], _ = strconv.ParseUint(f[1], 10, 64)
		}
	}
	return out
}
func ReadStats(p string) Stats {
	cpu := readKV(p, "cpu.stat")
	events := readKV(p, "memory.events")
	return Stats{cpu["usage_usec"], cpu["throttled_usec"], cpu["nr_throttled"], readNum(p, "memory.current"), readNum(p, "memory.peak"), events["oom_kill"], readNum(p, "pids.current")}
}
