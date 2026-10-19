package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDropAmbientCapsReachesChildren(t *testing.T) {
	if err := dropAmbientCaps(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		out, err := exec.Command("grep", "CapAmb", "/proc/self/status").Output()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "0000000000000000") {
			t.Fatalf("child still has ambient caps: %s", out)
		}
	}
}
