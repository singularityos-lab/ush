// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package response holds the shared "do something about a bad process" actions:
// killing a process tree and freezing/thawing it via the cgroup v2 freezer.
//
// Used by resourceguard (CPU/RAM limits) and by the Singularity Guard daemon
// (singd) when its behavioural correlator decides a process tree must be
// stopped, so both share one implementation of /proc walking and signalling.
package response

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Descendants returns all descendant PIDs of pid (not including pid itself),
// discovered via /proc/<pid>/task/<tid>/children.
func Descendants(pid int) []int {
	var result []int
	seen := map[int]bool{pid: true}
	stack := []int{pid}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		childrenPath := filepath.Join("/proc", strconv.Itoa(cur), "task", strconv.Itoa(cur), "children")
		data, err := os.ReadFile(childrenPath)
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(data)) {
			cpid, _ := strconv.Atoi(f)
			if cpid > 0 && !seen[cpid] {
				seen[cpid] = true
				result = append(result, cpid)
				stack = append(stack, cpid)
			}
		}
	}
	return result
}

// KillTree SIGKILLs pid and all of its descendants. Descendants are collected
// before any signal is sent, so reparenting during the kill cannot let a child
// escape. Errors on individual kills are ignored (the process may already be
// gone); the first hard error is returned.
func KillTree(pid int) error {
	pids := append(Descendants(pid), pid)
	var firstErr error
	for _, p := range pids {
		if err := syscall.Kill(p, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Freeze suspends every task in the given cgroup v2 directory by writing "1" to
// its cgroup.freeze file. Best-effort: returns an error only if the freezer is
// not available. Useful to pause a suspicious process tree for inspection
// before deciding to kill or clear it.
func Freeze(cgroupDir string) error {
	return os.WriteFile(filepath.Join(cgroupDir, "cgroup.freeze"), []byte("1"), 0)
}

// Thaw resumes a frozen cgroup v2 directory.
func Thaw(cgroupDir string) error {
	return os.WriteFile(filepath.Join(cgroupDir, "cgroup.freeze"), []byte("0"), 0)
}
