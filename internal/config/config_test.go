package config

import (
	"math"
	"testing"
)

func TestValidation(t *testing.T) {
	for _, s := range []string{"../a", "", "/tmp", "a/b", "a,b", ".."} {
		if Name(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{"alpine", "demo-1", "a.b"} {
		if err := Name(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), 0, -1} {
		if (Limits{v, 64 << 20, 64}).Validate() == nil {
			t.Fatal("invalid CPU accepted")
		}
	}
	if (Limits{CPUs: 0.25}).CPUMax() != "25000 100000" {
		t.Fatal("quota")
	}
}
func TestBytes(t *testing.T) {
	for s, want := range map[string]int64{"64m": 64 << 20, "1GiB": 1 << 30, "1024": 1024} {
		got, err := Bytes(s)
		if err != nil || got != want {
			t.Fatalf("%s: %d %v", s, got, err)
		}
	}
	for _, s := range []string{"0", "-1m", "9223372036854775807g", "x", "1.5g"} {
		if _, err := Bytes(s); err == nil {
			t.Fatal(s)
		}
	}
}
