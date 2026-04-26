// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package pkg provides a semantic layer over apt/dpkg: persistent and
// ephemeral installs, burn, diff, and inspect.
package pkg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/singularityos-lab/ush/internal/broker"
	"github.com/singularityos-lab/ush/internal/fs"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"golang.org/x/sys/unix"
)

// ScriptRisk classifies the risk of a maintainer script.
type ScriptRisk string

const (
	RiskSafe  ScriptRisk = "SAFE"
	RiskWarn  ScriptRisk = "WARN"
	RiskBlock ScriptRisk = "BLOCK"
)

// Manager manages the ush package runtime.
type Manager struct {
	layerMgr     *fs.LayerManager
	sessionID    string
	pkgPrefix    string // dpkg --instdir: where installed files land
	brokerClient *broker.Client
	stdout       io.Writer
	stderr       io.Writer
}

// New creates a new package manager.
// pkgPrefix is the directory used as dpkg's instdir (e.g., layerMgr.PkgRootDir()).
func New(layerMgr *fs.LayerManager, sessionID, pkgPrefix string) *Manager {
	m := &Manager{
		layerMgr:  layerMgr,
		sessionID: sessionID,
		pkgPrefix: pkgPrefix,
	}
	// Clean up any conflicting core libs that may have been installed into
	// pkgroot by a previous run before path-exclude was in place.
	if pkgPrefix != "" {
		cleanupCoreLibsFromPkgroot(pkgPrefix)
	}
	return m
}

// SetBrokerClient connects the broker client to the package manager.
// If set, pkg install/update will ask for permission before using the network.
func (m *Manager) SetBrokerClient(c *broker.Client) {
	m.brokerClient = c
}

// Install installs one or more packages.
// If --one-time is present, uses an ephemeral layer.
func (m *Manager) Install(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	oneTime := false
	var pkgs []string

	for _, a := range args {
		if a == "--one-time" || a == "-t" {
			oneTime = true
		} else {
			// Resolve .deb paths to absolute: apt requires absolute paths
			// and relative paths break after pivot_root.
			if strings.HasSuffix(a, ".deb") {
				if abs, err := filepath.Abs(a); err == nil {
					a = abs
				}
			}
			pkgs = append(pkgs, a)
		}
	}

	if len(pkgs) == 0 {
		fmt.Fprintln(stderr, "pkg install: specify at least one package")
		return fmt.Errorf("no packages specified")
	}

	mode := "persistent"
	if oneTime {
		mode = "ephemeral (one-time)"
	}
	fmt.Fprintf(stdout, "pkg: installing %s: %s\n", mode, strings.Join(pkgs, " "))

	// Ask the host broker for network permission before touching the network.
	if m.brokerClient != nil {
		reason := "install " + strings.Join(pkgs, " ")
		if !m.brokerClient.IsAllowed("network", "apt", reason) {
			fmt.Fprintln(stderr, "pkg: network access denied by user")
			return fmt.Errorf("pkg install: permission denied")
		}
	}

	// If apt lists are empty/absent, run update automatically first.
	// skipPermCheck=true: user already approved network for this install.
	if aptListsEmpty() {
		fmt.Fprintln(stdout, "pkg: apt lists empty, running update...")
		if err := m.update(ctx, stdout, stderr, true); err != nil {
			fmt.Fprintf(stderr, "pkg: update failed: %v\n", err)
		}
	}

	// First: inspection and classification of maintainer scripts.
	for _, p := range pkgs {
		if err := m.checkMaintainerScripts(ctx, stdout, stderr, p); err != nil {
			// Non-fatal if pre-analysis fails.
			ushlog.Warn("pkg: maintainer script pre-analysis failed", "pkg", p, "err", err)
		}
	}

	// assemble the apt-get call
	// APT::Sandbox::User=root disables apt's privilege drop toward _apt
	// (uid 42), which fails in user namespace.
	// --instdir redirects package files to pkgPrefix (dedicated path outside
	// the read-only /usr of the guest, so they can be found at standard hardcoded paths).
	// --admindir=/var/lib/dpkg maintains the guest's dpkg database for
	// dependency resolution.
	// --force-script-chrootless executes maintainer scripts in the current environment
	// rather than chrooting into instdir.
	aptArgs := []string{
		"-o", "APT::Install-Recommends=false",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "APT::Sandbox::User=root",
		"-o", "DPkg::Pre-Invoke=",
		"-o", "DPkg::Post-Invoke=",
		"-o", "APT::Update::Pre-Invoke=",
		"-o", "APT::Update::Post-Invoke=",
		// Disable apt progress bars and status-fd output, we format our own.
		"-o", "APT::Status-Fd=0",
		"-o", "APT::Color=1",
		"-y", "install",
	}
	if m.pkgPrefix != "" {
		adminDir, err := ensurePkgAdminDir(m.pkgPrefix)
		if err != nil {
			ushlog.Warn("pkg: unable to create pkgPrefix admindir", "err", err)
		}
		if err := os.MkdirAll(m.pkgPrefix, 0755); err != nil {
			ushlog.Warn("pkg: unable to create pkgPrefix", "err", err)
		} else {
			aptArgs = append(aptArgs[:len(aptArgs)-2],
				"--reinstall",
				"-o", fmt.Sprintf("Dpkg::Options::=--instdir=%s", m.pkgPrefix),
				"-o", fmt.Sprintf("Dpkg::Options::=--admindir=%s", adminDir),
				// Point apt's own status view at the pkgroot database so that
				// dependency resolution uses ONLY packages we've installed into
				// pkgroot - not the host's installed packages at /var/lib/dpkg/status.
				"-o", fmt.Sprintf("Dir::State::status=%s/status", adminDir),
				"-o", "Dpkg::Options::=--force-script-chrootless",
				"-o", "Dpkg::Options::=--no-triggers",
				"-o", "Dpkg::Options::=--force-depends",
				"-o", "Dpkg::Options::=--path-exclude=/usr/share/man/*",
				"-o", "Dpkg::Options::=--path-exclude=/usr/share/doc/*",
				// Prevent core glibc runtime from being installed into pkgroot.
				// These would shadow the host's (newer) glibc and crash host binaries.
				"-o", "Dpkg::Options::=--path-exclude=/usr/lib/*/libc.so.6",
				"-o", "Dpkg::Options::=--path-exclude=/usr/lib/*/libc-*.so",
				"-o", "Dpkg::Options::=--path-exclude=/lib/*/libc.so.6",
				"-o", "Dpkg::Options::=--path-exclude=/usr/lib/*/ld-linux*.so*",
				"-o", "Dpkg::Options::=--path-exclude=/lib/*/ld-linux*.so*",
				"-o", "Dpkg::Options::=--path-exclude=/usr/lib/*/ld-*.so*",
				aptArgs[len(aptArgs)-2], aptArgs[len(aptArgs)-1],
			)
		}
	}
	aptArgs = append(aptArgs, pkgs...)

	if err := m.runApt(ctx, stdout, stderr, aptArgs...); err != nil {
		return fmt.Errorf("pkg install: %w", err)
	}

	// Remove core glibc runtime files that apt may have installed into pkgroot
	// despite the path-exclude options (some are installed as symlinks or via
	// triggers). These must come from the base system to avoid version conflicts.
	if m.pkgPrefix != "" {
		cleanupCoreLibsFromPkgroot(m.pkgPrefix)
	}

	// Bind-mount data directories from pkgroot/usr/share/* onto /usr/share/*
	// so installed binaries find their files at standard hardcoded paths.
	// In a mount namespace we are virtual root, so the mount is permitted.
	if m.pkgPrefix != "" {
		bindPkgShareDirs(m.pkgPrefix)
	}

	if !oneTime {
		for _, p := range pkgs {
			if err := m.layerMgr.AddPackage(p); err != nil {
				ushlog.Warn("pkg: unable to update manifest", "pkg", p, "err", err)
			}
		}
	}

	fmt.Fprintf(stdout, "pkg: %s installed successfully\n", strings.Join(pkgs, " "))
	return nil
}

// Update runs apt-get update to refresh package lists.
// If calledFromInstall is true, it skips the permission check (already asked by install).
func (m *Manager) Update(ctx context.Context, stdout, stderr io.Writer) error {
	return m.update(ctx, stdout, stderr, false)
}

func (m *Manager) update(ctx context.Context, stdout, stderr io.Writer, skipPermCheck bool) error {
	// Ask the host broker for network permission before touching the network.
	if !skipPermCheck && m.brokerClient != nil {
		if !m.brokerClient.IsAllowed("network", "apt", "update package lists") {
			fmt.Fprintln(stderr, "pkg: network access denied by user")
			return fmt.Errorf("pkg update: permission denied")
		}
	}
	fmt.Fprintln(stdout, "pkg: updating package lists...")
	return m.runApt(ctx, stdout, stderr, "-o", "APT::Sandbox::User=root", "update")
}

// aptListsEmpty returns true if apt lists are absent or empty.
func aptListsEmpty() bool {
	listDir := "/var/lib/apt/lists"
	entries, err := os.ReadDir(listDir)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), "_Packages") {
			return false
		}
	}
	return true
}

// Remove removes one or more packages from the layer.
func (m *Manager) Remove(ctx context.Context, stdout, stderr io.Writer, pkgs []string) error {
	if len(pkgs) == 0 {
		fmt.Fprintln(stderr, "pkg remove: specify at least one package")
		return fmt.Errorf("no packages")
	}

	fmt.Fprintf(stdout, "pkg: removing: %s\n", strings.Join(pkgs, " "))

	aptArgs := append([]string{"-y", "remove"}, pkgs...)
	if err := m.runApt(ctx, stdout, stderr, aptArgs...); err != nil {
		return fmt.Errorf("pkg remove: %w", err)
	}

	for _, p := range pkgs {
		m.layerMgr.RemovePackage(p)
	}

	return nil
}

// Fix repairs a broken dpkg state by running dpkg --configure -a
// via apt-get's DPkg::Options so all -o flags are valid apt options.
func (m *Manager) Fix(ctx context.Context, stdout, stderr io.Writer) error {
	fmt.Fprintln(stdout, "pkg: fixing broken dpkg state...")

	aptArgs := []string{
		"-o", "APT::Sandbox::User=root",
		"-o", "DPkg::Pre-Invoke=",
		"-o", "DPkg::Post-Invoke=",
		"-o", "APT::Update::Pre-Invoke=",
		"-o", "APT::Update::Post-Invoke=",
		"-o", "APT::Status-Fd=0",
		"-o", "APT::Color=1",
	}

	if m.pkgPrefix != "" {
		adminDir, err := ensurePkgAdminDir(m.pkgPrefix)
		if err != nil {
			ushlog.Warn("pkg: unable to create pkgPrefix admindir", "err", err)
		} else {
			aptArgs = append(aptArgs,
				"-o", fmt.Sprintf("Dpkg::Options::=--instdir=%s", m.pkgPrefix),
				"-o", fmt.Sprintf("Dpkg::Options::=--admindir=%s", adminDir),
				"-o", fmt.Sprintf("Dir::State::status=%s/status", adminDir),
				"-o", "Dpkg::Options::=--force-script-chrootless",
				"-o", "Dpkg::Options::=--no-triggers",
				"-o", "Dpkg::Options::=--force-depends",
			)
		}
	}

	// Use dpkg --configure -a via apt-get's internal dpkg invocation.
	aptArgs = append(aptArgs, "-y", "-f", "install")

	if err := m.runApt(ctx, stdout, stderr, aptArgs...); err != nil {
		// Fallback: run dpkg directly with --configure -a (no -o flags).
		ushlog.Warn("pkg fix: apt-get -f install failed, trying dpkg --configure -a directly", "err", err)
		return m.fixDirectDpkg(ctx, stdout, stderr)
	}

	fmt.Fprintln(stdout, "pkg: dpkg state repaired")
	return nil
}

// fixDirectDpkg runs dpkg --configure -a directly (no -o flags, dpkg doesn't accept them).
func (m *Manager) fixDirectDpkg(ctx context.Context, stdout, stderr io.Writer) error {
	args := []string{"--configure", "-a"}

	if m.pkgPrefix != "" {
		adminDir, err := ensurePkgAdminDir(m.pkgPrefix)
		if err == nil {
			args = append(args,
				"--instdir="+m.pkgPrefix,
				"--admindir="+adminDir,
				"--force-script-chrootless",
				"--no-triggers",
				"--force-depends",
			)
		}
	}

	dpkgBin := findAptBin("dpkg")
	if !strings.Contains(dpkgBin, "/") {
		return fmt.Errorf("dpkg not found")
	}

	hookDir := ""
	if m.pkgPrefix != "" {
		var cleanup func()
		var err error
		hookDir, cleanup, err = createPackageHookWrappers()
		if err != nil {
			return err
		}
		defer cleanup()
	}

	pathValue := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + os.Getenv("PATH")
	if hookDir != "" {
		pathValue = hookDir + ":" + pathValue
	}

	env := append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"DEBCONF_NONINTERACTIVE_SEEN=true",
		"DPKG_ROOT=",
		// dpkg maintainer scripts use ldconfig and start-stop-daemon
		// which live in /sbin and /usr/sbin, ensure they are on PATH.
		"PATH="+pathValue,
		"USH_PRELOAD_IDENTITY=root",
	)

	if shimEnv, err := preloadShimEnv(); err == nil {
		env = append(env, shimEnv)
	} else {
		return err
	}
	if m.pkgPrefix != "" {
		env = append(env, "USH_PKG_PREFIX="+m.pkgPrefix)
	}

	toolsDir := os.Getenv("USH_TOOLS_DIR")
	if toolsDir != "" && strings.HasPrefix(dpkgBin, toolsDir) {
		ldPath := filepath.Join(toolsDir, "usr", "lib", "x86_64-linux-gnu") + ":" +
			filepath.Join(toolsDir, "usr", "lib")
		if existing := os.Getenv("LD_LIBRARY_PATH"); existing != "" {
			ldPath += ":" + existing
		}
		env = append(env, "LD_LIBRARY_PATH="+ldPath)
	}

	cmd := exec.CommandContext(ctx, dpkgBin, args...)
	cmd.Stdout = newAptOutputFilter(stdout)
	cmd.Stderr = newAptOutputFilter(stderr)
	cmd.Env = env

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pkg fix: %w", err)
	}

	fmt.Fprintln(stdout, "pkg: dpkg state repaired")
	return nil
}
