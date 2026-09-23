package runtime

import (
	"github.com/dhruv/isolate/internal/config"
	"github.com/dhruv/isolate/internal/image"
	"os"
	"testing"
)

func TestImageDefaultsAndOverrides(t *testing.T) {
	s := config.Spec{ID: "x", Image: "y", UID: 65534, GID: 65534, Env: []string{"A=override"}, Limits: config.Limits{CPUs: 1, Memory: 64 << 20, Pids: 64}}
	m := image.Manifest{Cmd: []string{"default"}, Entrypoint: []string{"/entry"}, Env: []string{"A=image", "B=retained"}, Workdir: "/work"}
	got, err := resolve(s, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Args) != 2 || got.Args[0] != "/entry" || got.Args[1] != "default" || got.Workdir != "/work" {
		t.Fatalf("%+v", got)
	}
	env := map[string]bool{}
	for _, e := range got.Env {
		env[e] = true
	}
	if !env["A=override"] || !env["B=retained"] || env["A=image"] {
		t.Fatal(got.Env)
	}
	s.Args = []string{"explicit"}
	got, err = resolve(s, m)
	if err != nil || got.Args[1] != "explicit" {
		t.Fatal(got, err)
	}
}
func TestPIDIdentityRejectsReusedPID(t *testing.T) {
	ticks, err := startTicks(os.Getpid())
	if err != nil || ticks == "" {
		t.Fatal(ticks, err)
	}
	st := State{PID: os.Getpid(), StartTicks: "0"}
	if fd, err := liveFD(st); err == nil {
		t.Fatalf("accepted mismatched process identity, fd=%d", fd)
	}
}
