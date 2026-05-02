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
