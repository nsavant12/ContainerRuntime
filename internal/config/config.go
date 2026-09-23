// Package config defines and validates the public runtime configuration.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func Name(s string) error {
	if !validName.MatchString(s) {
		return fmt.Errorf("invalid name %q: use 1-64 letters, digits, dots, underscores or hyphens", s)
	}
	return nil
}
func ID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type Limits struct {
	CPUs   float64 `json:"cpus"`
	Memory int64   `json:"memory_bytes"`
	Pids   int64   `json:"pids"`
}

func (l Limits) Validate() error {
	if math.IsNaN(l.CPUs) || math.IsInf(l.CPUs, 0) || l.CPUs < 0.01 || l.CPUs > 1024 {
		return fmt.Errorf("cpus must be between 0.01 and 1024")
	}
	if l.Memory < 16<<20 {
		return fmt.Errorf("memory must be at least 16 MiB")
	}
	if l.Pids < 16 || l.Pids > 1<<20 {
		return fmt.Errorf("pids must be between 16 and 1048576")
	}
	return nil
}
func (l Limits) CPUMax() string { return fmt.Sprintf("%d 100000", int64(math.Round(l.CPUs*100000))) }
func Bytes(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	for _, v := range []struct {
		s string
		m int64
	}{{"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10}, {"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}} {
		if strings.HasSuffix(s, v.s) {
			s = strings.TrimSuffix(s, v.s)
			mult = v.m
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid memory size")
	}
	return n * mult, nil
}

type Spec struct {
	ID      string   `json:"id"`
	Image   string   `json:"image"`
	Args    []string `json:"args"`
	Env     []string `json:"env,omitempty"`
	Workdir string   `json:"workdir"`
	UID     int      `json:"uid"`
	GID     int      `json:"gid"`
	Limits  Limits   `json:"limits"`
}

func (s Spec) Validate() error {
	if err := Name(s.ID); err != nil {
		return err
	}
	if err := Name(s.Image); err != nil {
		return err
	}
	if err := s.Limits.Validate(); err != nil {
		return err
	}
	if s.UID < 0 || s.GID < 0 || int64(s.UID) > 4294967294 || int64(s.GID) > 4294967294 {
		return fmt.Errorf("uid/gid out of range")
	}
	if s.Workdir != "" && !filepath.IsAbs(s.Workdir) {
		return fmt.Errorf("workdir must be absolute")
	}
	for _, e := range s.Env {
		if !strings.Contains(e, "=") || strings.IndexByte(e, 0) >= 0 || strings.HasPrefix(e, "=") {
			return fmt.Errorf("invalid environment assignment %q", e)
		}
	}
	for _, a := range s.Args {
		if strings.IndexByte(a, 0) >= 0 {
			return fmt.Errorf("argument contains NUL")
		}
	}
	return nil
}
