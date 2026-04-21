// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package resourceguard monitors a guest process tree's CPU and memory usage
// and kills it only on memory exhaustion, warning via stderr. CPU is normalized
// to a share of the whole machine (a busy multi-core app is not "over the
// limit") and never kills on its own. Memory is measured on the guest tree
// itself, not the host as a whole; memory exhaustion, which freezes a system,
// is the only hard limit.
package resourceguard

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/response"
	"golang.org/x/sys/unix"
)

// Config for the resource guard. Percentages are of total machine capacity:
// CPUPercentMax against all cores combined, MemoryPercentMax against total RAM.
type Config struct {
	PID              int
	CheckInterval    time.Duration
	CPUPercentMax    float64
	MemoryPercentMax float64
	WarningWriter    fmt.Stringer
}

// Guard monitors resource usage of a PID and its children.
type Guard struct {
	cfg    Config
	stop   chan struct{}
	mu     sync.Mutex
	killed bool
}

// New creates a resource guard. The defaults only intervene at full saturation
// (100%): the guard is a runaway backstop, not a throttle on heavy apps.
func New(cfg Config) *Guard {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 2 * time.Second
	}
	if cfg.CPUPercentMax == 0 {
		cfg.CPUPercentMax = 100
	}
	if cfg.MemoryPercentMax == 0 {
		cfg.MemoryPercentMax = 100
	}
	return &Guard{cfg: cfg, stop: make(chan struct{})}
}

// Start begins periodic monitoring in a goroutine.
func (g *Guard) Start() {
	go g.run()
}

// Stop terminates monitoring.
func (g *Guard) Stop() {
	close(g.stop)
}

// WasKilled returns true if the guard killed the process.
func (g *Guard) WasKilled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.killed
}

func (g *Guard) run() {
	ncpu := float64(runtime.NumCPU())
	if ncpu < 1 {
		ncpu = 1
	}

	// Prefer the cgroup of the monitored process: when ush runs in its own
	// systemd scope, memory.current and cpu.stat give exact, kernel-accounted
	// figures for the whole app tree. Fall back to walking /proc otherwise.
	cg := cgroupOf(g.cfg.PID)

	cpuSeconds := func() float64 {
		if cg != "" {
			if usec, ok := cgroupCPUUsec(cg); ok {
				return float64(usec) / 1e6
			}
		}
		return totalCPUTime(g.cfg.PID)
	}
	memPercent := func() float64 {
		if cg != "" {
			if cur, ok := cgroupMemCurrent(cg); ok {
				if totalBytes := memTotalKB() * 1024.0; totalBytes > 0 {
					return float64(cur) / totalBytes * 100
				}
			}
		}
		return memoryTreePercent(g.cfg.PID)
	}

	prevCPU := cpuSeconds()
	prevTime := time.Now()

	ticker := time.NewTicker(g.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.stop:
			return
		case now := <-ticker.C:
			// CPU as a share of the whole machine (0..100%): a fully busy
			// 8-core app reads ~100%, not ~800%. Context only; never kills.
			curCPU := cpuSeconds()
			elapsed := now.Sub(prevTime).Seconds()
			cpuPct := 0.0
			if elapsed > 0 {
				cpuPct = ((curCPU - prevCPU) / elapsed) * 100 / ncpu
				if cpuPct < 0 {
					cpuPct = 0
				}
			}
			prevCPU = curCPU
			prevTime = now

			// Memory of the GUEST tree as a share of system RAM (not the host's
			// overall usage). Memory exhaustion is what actually freezes a
			// machine, so this is the only hard limit.
			memPct := memPercent()

			switch {
			case memPct >= g.cfg.MemoryPercentMax:
				ushlog.Warn("resourceguard: killing process tree (memory exhausted)",
					"pid", g.cfg.PID,
					"mem_pct", fmt.Sprintf("%.1f", memPct),
					"cpu_pct", fmt.Sprintf("%.1f", cpuPct),
				)
				fmt.Fprintf(os.Stderr,
					"\n\033[1;31mUSH: process killed: used %.0f%% of system memory (CPU %.0f%%)\033[0m\n",
					memPct, cpuPct,
				)
				response.KillTree(g.cfg.PID)
				g.mu.Lock()
				g.killed = true
				g.mu.Unlock()
				return
			case memPct >= g.cfg.MemoryPercentMax*0.9:
				fmt.Fprintf(os.Stderr,
					"\033[1;33mUSH: RAM %.0f%% of system memory, approaching limit (CPU %.0f%%)\033[0m\r",
					memPct, cpuPct,
				)
			}
		}
	}
}

// totalCPUTime reads total CPU time (user+sys, in seconds) for PID and all children.
func totalCPUTime(pid int) float64 {
	total := 0.0
	pids := collectDescendants(pid)
	pids = append(pids, pid)
	for _, p := range pids {
		statPath := filepath.Join("/proc", strconv.Itoa(p), "stat")
		data, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}
		fields := strings.Fields(string(data))
		if len(fields) < 17 {
			continue
		}
		utime, _ := strconv.ParseFloat(fields[13], 64)
		stime, _ := strconv.ParseFloat(fields[14], 64)
		total += (utime + stime) / getClockTicks()
	}
	return total
}

// memoryTreePercent returns the resident memory of pid and its descendants as a
// percentage of total system memory. It reads the resident pages from each
// /proc/<pid>/statm; shared pages are counted per process, so the figure is a
// slight over-estimate, which is the safe direction for a runaway backstop.
func memoryTreePercent(pid int) float64 {
	totalKB := memTotalKB()
	if totalKB == 0 {
		return 0
	}
	pids := collectDescendants(pid)
	pids = append(pids, pid)
	pageSize := int64(os.Getpagesize())
	var resident int64
	for _, p := range pids {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p), "statm"))
		if err != nil {
			continue
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			continue
		}
		pages, _ := strconv.ParseInt(fields[1], 10, 64) // field 2 = resident pages
		resident += pages * pageSize
	}
	return float64(resident) / (totalKB * 1024.0) * 100.0
}

// memTotalKB reads MemTotal (in kB) from /proc/meminfo.
func memTotalKB() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "MemTotal:" {
			v, _ := strconv.ParseFloat(parts[1], 64)
			return v
		}
	}
	return 0
}

// cgroupOf returns the cgroup-v2 directory of pid under /sys/fs/cgroup, or ""
// if it cannot be resolved or has no memory accounting (so the caller falls
// back to /proc). The unified hierarchy line in /proc/<pid>/cgroup is "0::<p>".
func cgroupOf(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		dir := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"))
		if _, err := os.Stat(filepath.Join(dir, "memory.current")); err == nil {
			return dir
		}
		return ""
	}
	return ""
}

// cgroupMemCurrent reads memory.current (bytes) from a cgroup directory.
func cgroupMemCurrent(dir string) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// cgroupCPUUsec reads the cumulative usage_usec from a cgroup's cpu.stat.
func cgroupCPUUsec(dir string) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "usage_usec" {
			v, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// collectDescendants finds all descendant PIDs of pid. Thin wrapper over the
// shared implementation in internal/response.
func collectDescendants(pid int) []int {
	return response.Descendants(pid)
}

var clockTicks float64

func getClockTicks() float64 {
	if clockTicks == 0 {
		var si unix.Sysinfo_t
		if err := unix.Sysinfo(&si); err == nil {
			clockTicks = 100.0
		} else {
			clockTicks = 100.0
		}
	}
	return clockTicks
}
