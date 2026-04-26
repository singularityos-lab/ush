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

// FixBroken runs apt-get install -f to resolve broken dependencies.
func (m *Manager) FixBroken(ctx context.Context, stdout, stderr io.Writer) error {
	fmt.Fprintln(stdout, "pkg: resolving broken dependencies...")

	aptArgs := []string{
		"-o", "APT::Install-Recommends=false",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "APT::Sandbox::User=root",
		"-o", "DPkg::Pre-Invoke=",
		"-o", "DPkg::Post-Invoke=",
		"-o", "APT::Update::Pre-Invoke=",
		"-o", "APT::Update::Post-Invoke=",
		"-o", "APT::Status-Fd=0",
		"-o", "APT::Color=1",
		"-y", "-f", "install",
	}

	if err := m.runApt(ctx, stdout, stderr, aptArgs...); err != nil {
		return fmt.Errorf("pkg fix: %w", err)
	}

	fmt.Fprintln(stdout, "pkg: broken dependencies resolved")
	return nil
}

// Burn destroys a package's files in the layer (does not perform dpkg --remove).
func (m *Manager) Burn(ctx context.Context, stdout, stderr io.Writer, pkgs []string) error {
	if len(pkgs) == 0 {
		fmt.Fprintln(stderr, "pkg burn: specify at least one package")
		return fmt.Errorf("no packages")
	}

	for _, p := range pkgs {
		fmt.Fprintf(stdout, "pkg: burn %s...\n", p)

		files, err := dpkgListFiles(p)
		if err != nil {
			fmt.Fprintf(stderr, "pkg burn: unable to get files for %s: %v\n", p, err)
			continue
		}

		// Remove files from the upper layer (if they exist).
		burned := 0
		for _, f := range files {
			// Look in the persistent upper layer.
			upperPath := filepath.Join(m.layerMgr.PersistentUpper(), f)
			if err := os.Remove(upperPath); err == nil {
				burned++
			}
		}

		fmt.Fprintf(stdout, "pkg: burn %s: removed %d files from layer\n", p, burned)
		m.layerMgr.RemovePackage(p)
	}

	return nil
}

// Diff shows the delta of the persistent layer compared to the base.
func (m *Manager) Diff(ctx context.Context, stdout io.Writer) error {
	files, err := m.layerMgr.Diff()
	if err != nil {
		return err
	}

	if len(files) == 0 {
		fmt.Fprintln(stdout, "pkg diff: no changes from base system")
		return nil
	}

	fmt.Fprintf(stdout, "pkg diff: %d files modified/added in layer:\n", len(files))
	for _, f := range files {
		fmt.Fprintf(stdout, "  + %s\n", f)
	}
	return nil
}

// Inspect shows detailed information about a package.
func (m *Manager) Inspect(ctx context.Context, stdout, stderr io.Writer, pkg string) error {
	fmt.Fprintf(stdout, "=== pkg inspect: %s ===\n\n", pkg)

	// dpkg info.
	dpkgInfo, err := runCmdOutput("dpkg", "-s", pkg)
	if err != nil {
		fmt.Fprintf(stdout, "dpkg status: not installed\n")
	} else {
		fmt.Fprintf(stdout, "dpkg status:\n%s\n", indent(dpkgInfo, "  "))
	}

	// Installed files.
	files, err := dpkgListFiles(pkg)
	if err == nil && len(files) > 0 {
		fmt.Fprintf(stdout, "\nInstalled files (%d):\n", len(files))
		for _, f := range files {
			if len(f) > 0 {
				fmt.Fprintf(stdout, "  %s\n", f)
			}
		}
	}

	// Maintainer scripts.
	scripts := []string{"preinst", "postinst", "prerm", "postrm", "config"}
	hasScripts := false
	for _, s := range scripts {
		path := filepath.Join("/var/lib/dpkg/info", pkg+"."+s)
		if _, err := os.Stat(path); err == nil {
			if !hasScripts {
				fmt.Fprintf(stdout, "\nMaintainer scripts:\n")
				hasScripts = true
			}
			risk := classifyScript(path)
			fmt.Fprintf(stdout, "  [%s] %s\n", risk, s)
		}
	}

	// Systemd units created by the package.
	units := findUnits(pkg)
	if len(units) > 0 {
		fmt.Fprintf(stdout, "\nUnit systemd:\n")
		for _, u := range units {
			fmt.Fprintf(stdout, "  %s\n", u)
		}
	}

	return nil
}

// Freeze promotes the ephemeral layer of the current session to persistent.
func (m *Manager) Freeze(ctx context.Context, stdout io.Writer) error {
	if m.sessionID == "" {
		return fmt.Errorf("pkg freeze: no active ephemeral session")
	}
	if err := m.layerMgr.FreezeEphemeral(m.sessionID); err != nil {
		return fmt.Errorf("pkg freeze: %w", err)
	}
	fmt.Fprintln(stdout, "pkg: ephemeral layer promoted to persistent")
	return nil
}

// List lists the packages installed in the persistent layer.
func (m *Manager) List(ctx context.Context, stdout io.Writer) error {
	pkgs, err := m.layerMgr.ListPackages()
	if err != nil {
		return err
	}
	if len(pkgs) == 0 {
		fmt.Fprintln(stdout, "pkg: no packages installed in layer")
		return nil
	}
	fmt.Fprintf(stdout, "Packages installed in layer (%d):\n", len(pkgs))
	for _, p := range pkgs {
		fmt.Fprintf(stdout, "  %s\n", p)
	}
	return nil
}

// checkMaintainerScripts analyzes the maintainer scripts of a package
// before installation and logs/blocks based on risk.
func (m *Manager) checkMaintainerScripts(ctx context.Context, stdout, stderr io.Writer, pkg string) error {
	// Download the package without installing to extract its scripts.
	tmpDir, err := os.MkdirTemp("", "ush-pkg-inspect-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// apt-get download.
	dlOut, dlErr := runCmdOutput("apt-get", "download", pkg)
	if dlErr != nil {
		ushlog.Debug("pkg: download pre-check failed", "pkg", pkg, "err", dlErr, "out", dlOut)
		return nil
	}

	// Extract the .deb.
	debs, _ := filepath.Glob("*.deb")
	if len(debs) == 0 {
		return nil
	}

	debPath := debs[0]
	defer os.Remove(debPath)

	// Extract only control.tar.
	runCmdIn(tmpDir, "dpkg-deb", "--control", debPath, filepath.Join(tmpDir, "control"))

	// Analyze each script.
	scriptNames := []string{"preinst", "postinst", "prerm", "postrm"}
	for _, sname := range scriptNames {
		spath := filepath.Join(tmpDir, "control", sname)
		data, err := os.ReadFile(spath)
		if err != nil {
			continue
		}

		risk := classifyScriptContent(string(data))

		ushlog.Info("pkg: maintainer script",
			"package", pkg,
			"script", sname,
			"risk", risk,
			"size_bytes", len(data),
		)

		switch risk {
		case RiskWarn:
			fmt.Fprintf(stdout, "pkg: %s.%s requires attention (WARN)\n", pkg, sname)
			fmt.Fprintf(stdout, "   Some sensitive operations detected. Continuing...\n")
		case RiskBlock:
			fmt.Fprintf(stderr, "pkg:  %s.%s contains high-risk operations (BLOCK)\n", pkg, sname)
			fmt.Fprintf(stderr, "   Operations detected: setuid, capabilities, module loading.\n")
			fmt.Fprintf(stderr, "   The broker will request user authorization.\n")
		}
	}

	return nil
}

// runApt executes apt-get inside the guest with security flags.
func (m *Manager) runApt(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	ushlog.Info("pkg: apt-get", "args", args)

	// Verify apt-get is available - bootstrap may have failed on first run.
	aptBin := findAptBin("apt-get")
	if !strings.Contains(aptBin, "/") {
		return fmt.Errorf("apt-get not found; USH downloads it automatically on first run, restart with internet access to complete setup")
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
		"APT_LISTCHANGES_FRONTEND=none",
		"APT_LISTBUGS_FRONTEND=none",
		// Clear DPKG_ROOT for maintainer scripts: with --instdir, dpkg sets
		// it to prefix but scripts (e.g. man-db postinst via debconf) look
		// for config in $DPKG_ROOT/etc/ which doesn't exist in pkgprefix.
		"DPKG_ROOT=",
		// dpkg maintainer scripts use ldconfig and start-stop-daemon
		// which live in /sbin and /usr/sbin, ensure they are on PATH.
		"PATH="+pathValue,
		"USH_PRELOAD_IDENTITY=root",
	)

	// Inject the LD_PRELOAD shim if it exists. dpkg maintainer scripts
	// (and dpkg itself) call chown/chmod/unlink/symlink/rename on RO paths
	// and with unmapped GIDs, all fail in user namespace and abort install.
	// Use the LD_PRELOAD shim from the guest-accessible path.
	if shimEnv, err := preloadShimEnv(); err == nil {
		env = append(env, shimEnv)
	} else {
		return err
	}
	if m.pkgPrefix != "" {
		env = append(env, "USH_PKG_PREFIX="+m.pkgPrefix)
	}

	// Search for apt-get in cascade: /run/ush/exec (real binary saved by fs setup,
	// not obscured by the overlay wrapper on /usr/bin) -> /usr/local/bin -> /usr/bin.
	toolsDir := os.Getenv("USH_TOOLS_DIR")
	isBootstrapped := toolsDir != "" && (strings.HasPrefix(aptBin, toolsDir) || aptBin == "/run/ush/exec/apt-get")
	if isBootstrapped {
		toolsLib := filepath.Join(toolsDir, "usr", "lib", "x86_64-linux-gnu")
		toolsLib2 := filepath.Join(toolsDir, "usr", "lib")
		existing := os.Getenv("LD_LIBRARY_PATH")
		ldPath := toolsLib + ":" + toolsLib2
		if existing != "" {
			ldPath += ":" + existing
		}
		env = append(env, "LD_LIBRARY_PATH="+ldPath)

		toolsBin := filepath.Join(toolsDir, "usr", "bin")
		dpkgPath := toolsBin + ":/usr/sbin:/usr/bin:/sbin:/bin"
		if hookDir != "" {
			dpkgPath = hookDir + ":" + dpkgPath
		}

		extraArgs := []string{}

		// Only point apt to bootstrapped dpkg if it actually exists there.
		bootDpkg := filepath.Join(toolsDir, "usr", "bin", "dpkg")
		if _, err := os.Stat(bootDpkg); err == nil {
			extraArgs = append(extraArgs,
				"-o", "Dir::Bin::dpkg="+bootDpkg,
			)
		}
		bootDpkgDeb := filepath.Join(toolsDir, "usr", "bin", "dpkg-deb")
		if _, err := os.Stat(bootDpkgDeb); err == nil {
			extraArgs = append(extraArgs,
				"-o", "Dir::Bin::dpkg-deb="+bootDpkgDeb,
			)
		}
		extraArgs = append(extraArgs, "-o", "Dpkg::Path="+dpkgPath)

		// Only override methods dir if the bootstrapped methods exist.
		// Otherwise, fall back to the system methods (which are bind-mounted RO).
		bootMethods := filepath.Join(toolsDir, "usr", "lib", "apt", "methods")
		if _, err := os.Stat(filepath.Join(bootMethods, "http")); err == nil {
			extraArgs = append([]string{"-o", "Dir::Bin::Methods=" + bootMethods}, extraArgs...)
		}

		args = append(extraArgs, args...)
	}

	// Disable dpkg's PTY allocation: in a user namespace the slave side can
	// stall maintainer scripts, and we already capture stdout/stderr via
	// pipes so the PTY buys us nothing.
	args = append([]string{"-o", "Dpkg::Use-Pty=0"}, args...)

	cmd := exec.CommandContext(ctx, aptBin, args...)
	// Detach from the interactive terminal stdin so maintainer scripts that
	// read from stdin (despite DEBIAN_FRONTEND=noninteractive) get EOF
	// immediately instead of hanging forever.
	if devNull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
	}
	cmd.Stdout = io.MultiWriter(newAptOutputFilter(stdout), newScriptLogger("apt-get"))
	cmd.Stderr = newAptOutputFilter(stderr)
	cmd.Env = env

	return cmd.Run()
}

// findAptBin finds the real apt/dpkg binary (not the blocking wrapper).
func findAptBin(name string) string {
	candidates := []string{
		"/run/ush/exec/" + name,
		"/usr/local/bin/" + name,
		"/usr/bin/" + name,
		"/bin/" + name,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name // let the OS produce the error
}
