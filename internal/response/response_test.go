// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package response

import (
	"os/exec"
	"testing"
	"time"
)

func TestDescendantsSelf(t *testing.T) {
	// Our own PID should have no recorded children in a fresh test process,
	// and the call must never include the pid itself.
	for _, p := range Descendants(1) {
		if p == 1 {
			t.Fatalf("Descendants must not include the root pid")
		}
	}
}

func TestKillTree(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	pid := cmd.Process.Pid

	if err := KillTree(pid); err != nil {
		t.Fatalf("KillTree: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		// killed as expected (Wait returns a signal error)
	case <-time.After(5 * time.Second):
		t.Fatal("process still alive after KillTree")
	}
}
