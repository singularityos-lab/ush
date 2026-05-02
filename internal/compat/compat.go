// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package compat implements compatibility profiles and diagnostics
// for packages in the ush runtime.
//
// Not all packages work in a systemd --user environment without
// a full boot. This package classifies incompatibilities,
// provides diagnostics, and builds an automated test suite.
package compat

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CompatLevel describes the expected compatibility level of a package.
type CompatLevel string

const (
	CompatFull    CompatLevel = "FULL"    // works fully
	CompatPartial CompatLevel = "PARTIAL" // works but with known limitations
	CompatBroken  CompatLevel = "BROKEN"  // does not work (explanation available)
	CompatUnknown CompatLevel = "UNKNOWN" // not yet tested
)

// IncompatibilityReason describes the cause of the incompatibility.
type IncompatibilityReason string

const (
	ReasonNeedsSystemBus    IncompatibilityReason = "requires D-Bus system bus"
	ReasonNeedsSystemd      IncompatibilityReason = "assumes system systemd (not --user)"
	ReasonNeedsRoot         IncompatibilityReason = "requires real host root"
	ReasonNeedsKernelModule IncompatibilityReason = "loads kernel modules"
	ReasonNeedsNetBind      IncompatibilityReason = "requires binding to port < 1024"
	ReasonNeedsFullProc     IncompatibilityReason = "reads host /proc (real PIDs)"
	ReasonNeedsDevAccess    IncompatibilityReason = "direct access to special /dev"
	ReasonNeedsSetuid       IncompatibilityReason = "requires setuid/capabilities"
	ReasonCgroupV2          IncompatibilityReason = "requires system cgroup v2"
)

// CompatProfile is the compatibility profile of a package.
type CompatProfile struct {
	Package     string                  `json:"package"`
	Level       CompatLevel             `json:"level"`
	Reasons     []IncompatibilityReason `json:"reasons,omitempty"`
	Notes       string                  `json:"notes,omitempty"`
	TestedAt    time.Time               `json:"tested_at,omitempty"`
	Workarounds []string                `json:"workarounds,omitempty"`
}

// Checker runs compatibility diagnostics for a package.
type Checker struct {
	stdout io.Writer
	stderr io.Writer
}

// NewChecker creates a new Checker.
func NewChecker(stdout, stderr io.Writer) *Checker {
	return &Checker{stdout: stdout, stderr: stderr}
}

// CheckPackage analyzes the compatibility of an installed package.
func (c *Checker) CheckPackage(ctx context.Context, pkgName string) (*CompatProfile, error) {
	profile := &CompatProfile{
		Package:  pkgName,
		Level:    CompatUnknown,
		TestedAt: time.Now(),
	}

	// Check whether the package is installed.
	if _, err := exec.LookPath("dpkg"); err == nil {
		out, err := exec.CommandContext(ctx, "dpkg", "-s", pkgName).Output()
		if err != nil || !strings.Contains(string(out), "Status: install ok installed") {
			return profile, fmt.Errorf("package %s not installed", pkgName)
		}
	}

	checks := []struct {
		fn func(string) (IncompatibilityReason, bool)
	}{
		{c.checkSystemBus},
		{c.checkSystemdSystem},
		{c.checkKernelModule},
		{c.checkSetuid},
		{c.checkProcAccess},
	}

	for _, chk := range checks {
		if reason, found := chk.fn(pkgName); found {
			profile.Reasons = append(profile.Reasons, reason)
		}
	}

	profile.Level = c.assessLevel(profile.Reasons)
	profile.Workarounds = c.suggestWorkarounds(profile.Reasons)

	return profile, nil
}

func (c *Checker) checkSystemBus(pkg string) (IncompatibilityReason, bool) {
	files, _ := dpkgListFiles(pkg)
	for _, f := range files {
		if strings.Contains(f, "/dbus-1/system.d/") ||
			strings.Contains(f, "/dbus-1/system-services/") {
			return ReasonNeedsSystemBus, true
		}
	}
	for _, script := range []string{"postinst", "preinst"} {
		path := fmt.Sprintf("/var/lib/dpkg/info/%s.%s", pkg, script)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if regexp.MustCompile(`dbus-daemon.*system|--system.*dbus`).Match(data) {
			return ReasonNeedsSystemBus, true
		}
	}
	return "", false
}

func (c *Checker) checkSystemdSystem(pkg string) (IncompatibilityReason, bool) {
	files, _ := dpkgListFiles(pkg)
	for _, f := range files {
		if strings.Contains(f, "/systemd/system/") {
			return ReasonNeedsSystemd, true
		}
	}
	return "", false
}

func (c *Checker) checkKernelModule(pkg string) (IncompatibilityReason, bool) {
	files, _ := dpkgListFiles(pkg)
	for _, f := range files {
		if strings.HasSuffix(f, ".ko") || strings.Contains(f, "/kernel/") {
			return ReasonNeedsKernelModule, true
		}
	}
	return "", false
}

func (c *Checker) checkSetuid(pkg string) (IncompatibilityReason, bool) {
	files, _ := dpkgListFiles(pkg)
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if info.Mode()&0o6000 != 0 {
			return ReasonNeedsSetuid, true
		}
	}
	return "", false
}

func (c *Checker) checkProcAccess(pkg string) (IncompatibilityReason, bool) {
	for _, script := range []string{"postinst", "preinst", "postrm"} {
		path := fmt.Sprintf("/var/lib/dpkg/info/%s.%s", pkg, script)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if regexp.MustCompile(`/proc/[0-9]+|ls /proc|cat /proc`).Match(data) {
			return ReasonNeedsFullProc, true
		}
	}
	return "", false
}

func (c *Checker) assessLevel(reasons []IncompatibilityReason) CompatLevel {
	if len(reasons) == 0 {
		return CompatFull
	}
	for _, r := range reasons {
		switch r {
		case ReasonNeedsKernelModule, ReasonNeedsRoot:
			return CompatBroken
		}
	}
	return CompatPartial
}

func (c *Checker) suggestWorkarounds(reasons []IncompatibilityReason) []string {
	var ws []string
	for _, r := range reasons {
		switch r {
		case ReasonNeedsSystemBus:
			ws = append(ws, "Configure the D-Bus proxy in the USH broker for this interface")
		case ReasonNeedsSystemd:
			ws = append(ws, "Use 'pkg inspect' to view units and enable them with systemctl --user")
		case ReasonNeedsSetuid:
			ws = append(ws, "Request device.access permission via USH broker")
		case ReasonNeedsFullProc:
			ws = append(ws, "The process will not see host PIDs - may work partially")
		case ReasonNeedsKernelModule:
			ws = append(ws, "Module loading not supported in guest - install the module on the host")
		}
	}
	return ws
}

// Report prints the compatibility report to w.
func (c *Checker) Report(w io.Writer, profile *CompatProfile) {
	levelColor := map[CompatLevel]string{
		CompatFull:    "\033[1;32m",
		CompatPartial: "\033[1;33m",
		CompatBroken:  "\033[1;31m",
		CompatUnknown: "\033[1;37m",
	}
	reset := "\033[0m"
	color := levelColor[profile.Level]

	fmt.Fprintf(w, "\n%s=== Compatibility: %s [%s]%s\n\n",
		color, profile.Package, profile.Level, reset)

	if len(profile.Reasons) > 0 {
		fmt.Fprintln(w, "Issues detected:")
		for _, r := range profile.Reasons {
			fmt.Fprintf(w, "  - %s\n", r)
		}
		fmt.Fprintln(w)
	}

	if len(profile.Workarounds) > 0 {
		fmt.Fprintln(w, "Suggestions:")
		for _, ws := range profile.Workarounds {
			fmt.Fprintf(w, "  - %s\n", ws)
		}
		fmt.Fprintln(w)
	}

	if profile.Level == CompatFull {
		fmt.Fprintln(w, "  No compatibility issues detected.")
	}
}

// RunTestSuite runs the compatibility test suite for the package runtime.
func RunTestSuite(ctx context.Context, stdout io.Writer) error {
	testPkgs := []string{
		"curl", "wget", "git", "htop", "vim", "nano",
		"python3", "nodejs", "sqlite3",
		"nginx", "openssh-client",
	}

	checker := NewChecker(stdout, stdout)
	fmt.Fprintf(stdout, "=== USH compat test suite ===\n\n")

	results := map[CompatLevel]int{}
	for _, pkg := range testPkgs {
		profile, err := checker.CheckPackage(ctx, pkg)
		if err != nil {
			fmt.Fprintf(stdout, "  SKIP %s (%v)\n", pkg, err)
			continue
		}
		fmt.Fprintf(stdout, "  %-16s [%s]\n", pkg, profile.Level)
		results[profile.Level]++
	}

	fmt.Fprintf(stdout, "\nResults: FULL=%d PARTIAL=%d BROKEN=%d UNKNOWN=%d\n",
		results[CompatFull], results[CompatPartial],
		results[CompatBroken], results[CompatUnknown])
	return nil
}

// TestMaintainerScript statically analyzes a maintainer script.
func TestMaintainerScript(ctx context.Context, pkg, scriptName string, w io.Writer) error {
	scriptPath := filepath.Join("/var/lib/dpkg/info", pkg+"."+scriptName)
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("script not found: %s", scriptPath)
	}

	fmt.Fprintf(w, "=== Test maintainer script: %s.%s ===\n\n", pkg, scriptName)

	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Size: %d bytes\n", len(data))

	sensitivePattern := regexp.MustCompile(
		`systemctl|dbus|modprobe|insmod|chmod\s+[+]s|setcap|adduser|useradd|/proc/sys`,
	)
	lines := strings.Split(string(data), "\n")
	sensitiveLines := []string{}
	for i, line := range lines {
		if sensitivePattern.MatchString(line) {
			sensitiveLines = append(sensitiveLines, fmt.Sprintf("  L%d: %s", i+1, line))
		}
	}

	if len(sensitiveLines) > 0 {
		fmt.Fprintf(w, "\nSensitive lines (%d):\n", len(sensitiveLines))
		for _, l := range sensitiveLines {
			fmt.Fprintln(w, l)
		}
	} else {
		fmt.Fprintln(w, "\nNo sensitive lines detected.")
	}
	return nil
}

func dpkgListFiles(pkg string) ([]string, error) {
	out, err := exec.Command("dpkg", "-L", pkg).Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "/" {
			files = append(files, line)
		}
	}
	return files, nil
}
