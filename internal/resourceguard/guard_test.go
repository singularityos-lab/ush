// SPDX-License-Identifier: GPL-3.0-or-later

package resourceguard

import (
	"os"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	g := New(Config{PID: 1})
	if g.cfg.CheckInterval != 2*time.Second {
		t.Errorf("default CheckInterval = %v, want 2s", g.cfg.CheckInterval)
	}
	if g.cfg.CPUPercentMax != 100 {
		t.Errorf("default CPUPercentMax = %v, want 100", g.cfg.CPUPercentMax)
	}
	if g.cfg.MemoryPercentMax != 100 {
		t.Errorf("default MemoryPercentMax = %v, want 100", g.cfg.MemoryPercentMax)
	}
}

func TestStop(t *testing.T) {
	g := New(Config{PID: 1, CheckInterval: 100 * time.Millisecond})
	g.Start()
	time.Sleep(50 * time.Millisecond)
	g.Stop()
	if g.WasKilled() {
		t.Error("PID 1 should not be killed")
	}
}

func TestMemoryTreePercent(t *testing.T) {
	// Our own process tree must use a sane, positive fraction of system RAM,
	// far below the 100% kill threshold.
	pct := memoryTreePercent(os.Getpid())
	if pct <= 0 {
		t.Errorf("memoryTreePercent(self) = %v, want > 0", pct)
	}
	if pct >= 100 {
		t.Errorf("memoryTreePercent(self) = %v, should be well under 100", pct)
	}
}

func TestMemTotalKB(t *testing.T) {
	if kb := memTotalKB(); kb <= 0 {
		t.Errorf("memTotalKB() = %v, want > 0", kb)
	}
}

func TestCollectDescendants(t *testing.T) {
	pids := collectDescendants(1)
	_ = pids
}

func TestTotalCPUTime(t *testing.T) {
	tick := totalCPUTime(1)
	if tick < 0 {
		t.Errorf("totalCPUTime(1) = %v, want >= 0", tick)
	}
}
