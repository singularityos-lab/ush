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
				// In the dsh (dev) profile the caller keeps its real uid instead of
				// mapping to 0, so dpkg's superuser check would abort the install.
				// instdir/admindir already point at a user-writable pkgroot, so let
				// dpkg proceed unprivileged; ignored (harmless) when already root.
				"-o", "Dpkg::Options::=--force-not-root",
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
		// dev (dsh) toolchain: the glibc runtime stays excluded (host-shadow safety),
		// but the dev linker-script needs a libc.so.6 target. Symlink it to the host
		// glibc exposed by the /usr overlay lower, AFTER cleanup so it is not removed.
		if os.Getenv("USH_PROFILE") == "dev" {
			ensureDevGlibcSymlinks(m.pkgPrefix)
		}
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
	args := []string{"-o", "APT::Sandbox::User=root"}
	// apt's pkgInitSystem needs a valid dpkg status file to initialize the
	// debian packaging system; without it `update` fails with "Unable to
	// determine a suitable packaging system type" while `install` (which sets
	// this) works. Point it at the pkgroot admindir like install does.
	if m.pkgPrefix != "" {
		if adminDir, err := ensurePkgAdminDir(m.pkgPrefix); err == nil {
			args = append(args, "-o", fmt.Sprintf("Dir::State::status=%s/status", adminDir))
		}
	}
	args = append(args, "update")
	return m.runApt(ctx, stdout, stderr, args...)
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

	env := append(cleanAptEnv(),
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

	// apt-get download. Apply the same security hardening as runApt (flags AND a
	// clean env) so this pre-check cannot fetch from an unauthenticated repo via
	// sources.list.d or an injected APT_CONFIG.
	dlArgs := append(aptSecurityFlags(), "download", pkg)
	dlCmd := exec.Command("apt-get", dlArgs...)
	dlCmd.Env = cleanAptEnv()
	dlOutBytes, dlErr := dlCmd.Output()
	dlOut := string(dlOutBytes)
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

// aptSecurityFlags force EVERY apt invocation to ignore the legacy trusted
// keyrings (Dir::Etc::trusted / trustedparts) and the sources.list.d directory
// (Dir::Etc::sourceparts), so apt honours only our signed-by verified
// sources.list. These must be applied to every apt call -- runApt AND the
// apt-get download pre-check -- or a leftover/planted repo re-enters through the
// path that misses them.
func aptSecurityFlags() []string {
	return []string{
		"-o", "Dir::Etc::trusted=/dev/null",
		"-o", "Dir::Etc::trustedparts=/dev/null",
		"-o", "Dir::Etc::sourceparts=/dev/null",
		// Pin the source list too: a command-line -o outranks any apt.conf.d or
		// APT_CONFIG file, so apt reads only our verified sources.list even if
		// something tries to redirect Dir::Etc::sourcelist elsewhere.
		"-o", "Dir::Etc::sourcelist=/etc/apt/sources.list",
	}
}

// cleanAptEnv returns the current environment with APT_CONFIG removed. A
// caller-supplied APT_CONFIG points apt at an arbitrary config file that can
// redefine Dir::Etc::sourcelist, the keyring, or the gpgv command and thereby
// bypass signature enforcement; strip it from every apt invocation.
func cleanAptEnv() []string {
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "APT_CONFIG=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// runApt executes apt-get inside the guest with security flags.
func (m *Manager) runApt(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	// Lead with the unconditional security hardening so it applies whether or not
	// the bootstrapped-tools branch is taken.
	args = append(aptSecurityFlags(), args...)
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

	env := append(cleanAptEnv(),
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
		// apt-get runs inside the guest namespace, where the staged libs are
		// bind-mounted at /run/ush/exec/lib (blockPackageManagers). The host
		// toolsDir path is not visible there, so the guest path must lead.
		const guestExec = "/run/ush/exec"
		guestLib := guestExec + "/lib"
		toolsLib := filepath.Join(toolsDir, "usr", "lib", "x86_64-linux-gnu")
		toolsLib2 := filepath.Join(toolsDir, "usr", "lib")
		existing := os.Getenv("LD_LIBRARY_PATH")
		ldPath := guestLib + ":" + guestLib + "/x86_64-linux-gnu:" + toolsLib + ":" + toolsLib2
		if existing != "" {
			ldPath += ":" + existing
		}
		env = append(env, "LD_LIBRARY_PATH="+ldPath)
		// dpkg reads its architecture tables from DPKG_DATADIR; point it at the
		// guest-staged copy so `dpkg --print-architecture` works and apt can
		// determine the packaging system on the non-Debian guest.
		env = append(env, "DPKG_DATADIR="+guestExec+"/share/dpkg")
		// Prepend the guest exec dir to PATH so dpkg finds its staged helpers
		// (dpkg-deb, dpkg-split) and the no-op ldconfig stub during configure.
		env = append(env, "PATH="+guestExec+":"+os.Getenv("PATH"))

		// runApt executes INSIDE the namespace, where toolsDir is not visible (ush
		// write-isolates it); the real apt/dpkg tools are bind-staged at
		// /run/ush/exec. Reference those guest paths, or the -o overrides that probe
		// toolsDir silently drop and apt/dpkg fall back to absent /usr paths.
		dpkgPath := guestExec + ":/usr/sbin:/usr/bin:/sbin:/bin"
		if hookDir != "" {
			dpkgPath = hookDir + ":" + dpkgPath
		}

		extraArgs := []string{}

		// The guest is not Debian, so apt cannot infer the arch from the base
		// system: without this it fails with "Unable to determine a suitable
		// packaging system type" / "Error reading the CPU table". The bootstrap
		// only fetches amd64 packages, so pin it explicitly.
		extraArgs = append(extraArgs, "-o", "APT::Architecture=amd64")

		// apt 2.6 still shells out to apt-key at a hard-coded /usr/bin path for
		// the clearsigned InRelease check; point it at the staged copy so it can
		// run (it in turn calls the staged gpgv against the [signed-by] keyring).
		// The trusted-keyring / sources.list.d hardening is applied unconditionally
		// to EVERY apt invocation (runApt + the download pre-check) via
		// aptSecurityFlags(), not just this bootstrapped path.
		extraArgs = append(extraArgs,
			"-o", "Dir::Bin::apt-key="+guestExec+"/apt-key",
			"-o", "APT::Key::gpgvcommand="+guestExec+"/gpgv",
		)

		// libapt-pkg reads the arch tables from the hard-coded /usr/share/dpkg,
		// which does not exist on the non-Debian guest -> "Error reading the CPU
		// table". Point apt straight at the staged tables so it never needs that
		// path (nor a working dpkg) just to determine the architecture.
		dpkgData := guestExec + "/share/dpkg"
		extraArgs = append(extraArgs,
			"-o", "Dir::dpkg::cputable="+dpkgData+"/cputable",
			"-o", "Dir::dpkg::tupletable="+dpkgData+"/tupletable",
			"-o", "Dir::dpkg::triplettable="+dpkgData+"/tupletable",
		)

		// The guest's /var/lib is read-only and has no /var/lib/apt, so apt cannot
		// create its lists/archives there ("List directory .../partial is missing").
		// Redirect apt's state and cache to a writable path under the ush home and
		// pre-create the partial dirs apt downloads into.
		aptState := filepath.Join(filepath.Dir(toolsDir), "apt-state")
		os.MkdirAll(filepath.Join(aptState, "lists", "partial"), 0755)    //nolint:errcheck
		os.MkdirAll(filepath.Join(aptState, "archives", "partial"), 0755) //nolint:errcheck
		os.MkdirAll(filepath.Join(aptState, "log"), 0755)                 //nolint:errcheck
		os.MkdirAll(filepath.Join(aptState, "cache"), 0755)               //nolint:errcheck
		// Point apt's whole state/cache/log tree at the writable dir: besides the
		// lists, apt also writes extended_states (Dir::State) and term/eipp logs
		// (Dir::Log), both of which live under the read-only /var on the guest.
		extraArgs = append(extraArgs,
			"-o", "Dir::State="+aptState,
			"-o", "Dir::State::lists="+filepath.Join(aptState, "lists"),
			"-o", "Dir::Cache="+filepath.Join(aptState, "cache"),
			"-o", "Dir::Cache::archives="+filepath.Join(aptState, "archives"),
			"-o", "Dir::Log="+filepath.Join(aptState, "log"),
		)

		// Point apt at the guest-staged dpkg (blockPackageManagers copies it to
		// /run/ush/exec). Probe the guest path, not toolsDir.
		if _, err := os.Stat(guestExec + "/dpkg"); err == nil {
			extraArgs = append(extraArgs, "-o", "Dir::Bin::dpkg="+guestExec+"/dpkg")
		}
		if _, err := os.Stat(guestExec + "/dpkg-deb"); err == nil {
			extraArgs = append(extraArgs, "-o", "Dir::Bin::dpkg-deb="+guestExec+"/dpkg-deb")
		}
		extraArgs = append(extraArgs, "-o", "Dpkg::Path="+dpkgPath)

		// Point apt at the guest-staged method drivers (/run/ush/exec/apt-methods).
		// Probe the GUEST path: runApt runs in the namespace where toolsDir is not
		// visible, so a toolsDir stat fails and apt looks in absent /usr/lib/apt/methods.
		if _, err := os.Stat(guestExec + "/apt-methods/http"); err == nil {
			extraArgs = append([]string{"-o", "Dir::Bin::methods=" + guestExec + "/apt-methods"}, extraArgs...)
		}

		args = append(extraArgs, args...)
	}

	// Disable dpkg's PTY allocation: in a user namespace the slave side can
	// stall maintainer scripts, and we already capture stdout/stderr via
	// pipes so the PTY buys us nothing.
	args = append([]string{"-o", "Dpkg::Use-Pty=0"}, args...)

	ushlog.Debug("pkg: apt-get final", "bootstrapped", isBootstrapped, "args", args)
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

func preloadShimEnv() (string, error) {
	shimPath := "/run/ush/exec/ush-chown-shim.so"
	if _, err := os.Stat(shimPath); err != nil {
		return "", fmt.Errorf("LD_PRELOAD shim missing at %s: %w", shimPath, err)
	}
	return "LD_PRELOAD=" + shimPath, nil
}

func createPackageHookWrappers() (string, func(), error) {
	dir, err := os.MkdirTemp("", "ush-pkg-hooks-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("pkg hooks: %w", err)
	}

	cleanup := func() { os.RemoveAll(dir) }
	script := "#!/bin/sh\nexit 0\n"
	for _, name := range []string{
		"gtk-update-icon-cache",
		"update-alternatives",
		"update-desktop-database",
		"update-mime-database",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("pkg hooks: %w", err)
		}
	}

	return dir, cleanup, nil
}

// cleanupCoreLibsFromPkgroot removes glibc runtime files from pkgroot that may
// have been installed there by apt/dpkg despite path-exclude options (e.g. via
// symlinks or triggers). These must come from the host base system only.
func cleanupCoreLibsFromPkgroot(pkgPrefix string) {
	globs := []string{
		"usr/lib/*/libc.so.6",
		"usr/lib/*/libc-*.so",
		"lib/*/libc.so.6",
		"usr/lib/*/ld-linux*.so*",
		"lib/*/ld-linux*.so*",
		"usr/lib/*/ld-*.so*",
	}
	for _, g := range globs {
		matches, err := filepath.Glob(filepath.Join(pkgPrefix, g))
		if err != nil {
			continue
		}
		for _, p := range matches {
			if err := os.Remove(p); err == nil {
				ushlog.Info("pkg: removed conflicting core lib from pkgroot", "path", p)
			}
		}
	}
}

// ensureDevGlibcSymlinks points the dev pkgroot's multiarch core libs at the host
// glibc. The Debian libc6 runtime is excluded from the pkgroot (host-shadow
// safety), so the libc6-dev linker-script's GROUP( /lib/x86_64-linux-gnu/libc.so.6 )
// has no target and linking fails. The guest is already merged-usr
// (/lib -> /usr/lib), so /lib/x86_64-linux-gnu/libc.so.6 resolves to
// /usr/lib/x86_64-linux-gnu/libc.so.6 in the overlay; a symlink there to the host
// glibc (/usr/lib/<lib>, exposed by the overlay lower) lets the link resolve. The
// loader is left untouched (host PT_INTERP), so link and run use one glibc and the
// host is never shadowed. Only libs the host actually provides are linked, so no
// dangling targets appear.
func ensureDevGlibcSymlinks(pkgPrefix string) {
	multiarch := filepath.Join(pkgPrefix, "usr", "lib", "x86_64-linux-gnu")
	if err := os.MkdirAll(multiarch, 0o755); err != nil {
		ushlog.Warn("pkg: dev glibc symlink dir failed", "dir", multiarch, "err", err)
		return
	}
	for _, lib := range []string{
		"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2",
		"librt.so.1", "libresolv.so.2", "libutil.so.1",
	} {
		target := filepath.Join("/usr/lib", lib)
		if _, err := os.Stat(target); err != nil {
			continue // host does not provide it; skip to avoid a dangling link
		}
		link := filepath.Join(multiarch, lib)
		if _, err := os.Lstat(link); err == nil {
			continue // real file or link already present
		}
		if err := os.Symlink(target, link); err != nil {
			ushlog.Warn("pkg: dev glibc symlink failed", "link", link, "target", target, "err", err)
		}
	}
	ushlog.Info("pkg: dev pkgroot core libs symlinked to host glibc", "dir", multiarch)
}

// bindPkgShareDirs overlays pkgPrefix/usr/share on top of /usr/share so package
// data files are visible at their hardcoded paths.
func bindPkgShareDirs(pkgPrefix string) {
	srcBase := filepath.Join(pkgPrefix, "usr", "share")
	if _, err := os.Stat(srcBase); err != nil {
		return
	}
	// Read-only overlay: pkgroot share dirs appear transparently on top.
	opts := fmt.Sprintf("lowerdir=%s:/usr/share,userxattr", srcBase)
	if err := unix.Mount("overlay", "/usr/share", "overlay", 0, opts); err != nil {
		// userxattr not supported - try without it (older kernels).
		opts = fmt.Sprintf("lowerdir=%s:/usr/share", srcBase)
		if err := unix.Mount("overlay", "/usr/share", "overlay", 0, opts); err != nil {
			ushlog.Warn("pkg: overlay /usr/share failed", "err", err)
		}
	}
}

// ensurePkgAdminDir creates (if it doesn't exist) a minimal dpkg admindir inside
// pkgPrefix. This admindir is separate from the system's /var/lib/dpkg: it tracks
// only what's installed in pkgPrefix, so apt doesn't confuse system packages with
// prefix packages.
// Returns the admindir path.
func ensurePkgAdminDir(pkgPrefix string) (string, error) {
	adminDir := filepath.Join(pkgPrefix, "var", "lib", "dpkg")
	dirs := []string{
		adminDir,
		filepath.Join(adminDir, "info"),
		filepath.Join(adminDir, "updates"),
		filepath.Join(adminDir, "triggers"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return adminDir, err
		}
	}
	// Create empty status if it doesn't exist (no packages installed in prefix).
	statusFile := filepath.Join(adminDir, "status")
	if _, err := os.Stat(statusFile); os.IsNotExist(err) {
		if err := os.WriteFile(statusFile, nil, 0644); err != nil {
			return adminDir, err
		}
	}
	// Create empty Unincorp.
	uninc := filepath.Join(adminDir, "triggers", "Unincorp")
	if _, err := os.Stat(uninc); os.IsNotExist(err) {
		os.WriteFile(uninc, nil, 0644) //nolint:errcheck
	}

	// dpkg sets DPKG_CHROOTDIR=pkgPrefix when running package scripts.
	// Modern debconf prepends DPKG_CHROOTDIR to /etc/debconf.conf, so it
	// looks for pkgPrefix/etc/debconf.conf - not the guest's /etc/debconf.conf.
	// Create a minimal working debconf.conf and database dirs here.
	if err := ensureDebconfInPkgroot(pkgPrefix); err != nil {
		ushlog.Warn("pkg: debconf setup in pkgroot failed", "err", err)
	}

	return adminDir, nil
}

// ensureDebconfInPkgroot creates the minimal debconf config and database
// directories needed by dpkg package scripts inside the pkgroot prefix.
func ensureDebconfInPkgroot(pkgPrefix string) error {
	// Try to copy the host's debconf.conf first (authoritative and complete).
	hostConf := "/etc/debconf.conf"
	dstConf := filepath.Join(pkgPrefix, "etc", "debconf.conf")
	if err := os.MkdirAll(filepath.Dir(dstConf), 0755); err != nil {
		return err
	}
	if _, err := os.Stat(dstConf); os.IsNotExist(err) {
		if data, err := os.ReadFile(hostConf); err == nil {
			os.WriteFile(dstConf, data, 0644) //nolint:errcheck
		} else {
			// Fallback: write a minimal debconf.conf.
			minimal := "# Debconf config\nConfig: configdb\nTemplates: templatedb\n\nName: configdb\nDriver: File\nMode: 644\nFilename: /var/cache/debconf/config.dat\n\nName: templatedb\nDriver: File\nMode: 644\nFilename: /var/cache/debconf/templates.dat\n"
			if err := os.WriteFile(dstConf, []byte(minimal), 0644); err != nil {
				return err
			}
		}
	}
	// Create the debconf database directory and empty database files.
	cacheDir := filepath.Join(pkgPrefix, "var", "cache", "debconf")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}
	for _, f := range []string{"config.dat", "templates.dat", "passwords.dat"} {
		p := filepath.Join(cacheDir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			os.WriteFile(p, nil, 0600) //nolint:errcheck
		}
	}
	return nil
}

// aptOutputFilter formats apt/dpkg output for the USH terminal.
// Strips carriage-return progress updates, suppresses blank lines from
// dpkg status messages, and color-codes key lines.
type aptOutputFilter struct {
	dst io.Writer
	buf bytes.Buffer
}

func newAptOutputFilter(dst io.Writer) *aptOutputFilter {
	return &aptOutputFilter{dst: dst}
}

func (f *aptOutputFilter) Write(p []byte) (int, error) {
	f.buf.Write(p)
	for {
		line, err := f.buf.ReadString('\n')
		if len(line) > 0 {
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				if err != nil {
					f.buf.WriteString(line)
				}
				continue
			}
			if strings.HasPrefix(trimmed, "pmstatus:") || strings.HasPrefix(trimmed, "status:") {
				if err != nil {
					f.buf.WriteString(line)
				}
				continue
			}
			if strings.HasPrefix(trimmed, "Setting up ") {
				trimmed = "\033[0;32m" + trimmed + "\033[0m"
			}
			if strings.HasPrefix(trimmed, "dpkg: error") || strings.HasPrefix(trimmed, "E: ") {
				trimmed = "\033[1;31m" + trimmed + "\033[0m"
			}
			if strings.Contains(trimmed, "chown:") || strings.Contains(trimmed, "changing ownership") {
				trimmed = "\033[2m" + trimmed + "\033[0m"
			}
			fmt.Fprintln(f.dst, trimmed)
		}
		if err != nil {
			f.buf.WriteString(line)
			break
		}
	}
	return len(p), nil
}

// scriptLogger is a writer that logs apt/dpkg output line by line.
type scriptLogger struct {
	name string
	buf  bytes.Buffer
}

func newScriptLogger(name string) *scriptLogger {
	return &scriptLogger{name: name}
}

func (sl *scriptLogger) Write(p []byte) (int, error) {
	sl.buf.Write(p)
	for {
		line, err := sl.buf.ReadString('\n')
		if len(line) > 0 {
			ushlog.Debug("pkg: apt output", "name", sl.name, "line", strings.TrimRight(line, "\n"))
		}
		if err != nil {
			sl.buf.WriteString(line)
			break
		}
	}
	return len(p), nil
}

// dpkgListFiles returns the files installed by a dpkg package.
func dpkgListFiles(pkg string) ([]string, error) {
	out, err := runCmdOutput("dpkg", "-L", pkg)
	if err != nil {
		return nil, err
	}
	var files []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != "/" {
			files = append(files, line)
		}
	}
	return files, nil
}

// classifyScript classifies the risk of a maintainer script from a file.
func classifyScript(path string) ScriptRisk {
	data, err := os.ReadFile(path)
	if err != nil {
		return RiskSafe
	}
	return classifyScriptContent(string(data))
}

// riskPatterns maps regex -> risk.
var riskPatterns = []struct {
	re   *regexp.Regexp
	risk ScriptRisk
}{
	// BLOCK
	{regexp.MustCompile(`chmod\s+[+]s|setcap|chown\s+root`), RiskBlock},
	{regexp.MustCompile(`modprobe|insmod|rmmod`), RiskBlock},
	{regexp.MustCompile(`/proc/sys/|/sys/`), RiskBlock},
	{regexp.MustCompile(`mknod\s`), RiskBlock},
	// WARN
	{regexp.MustCompile(`systemctl\s+(enable|start|stop|restart|daemon-reload)`), RiskWarn},
	{regexp.MustCompile(`dbus-send|gdbus\s+call`), RiskWarn},
	{regexp.MustCompile(`adduser|useradd|groupadd`), RiskWarn},
	{regexp.MustCompile(`update-rc\.d|invoke-rc\.d`), RiskWarn},
	{regexp.MustCompile(`ldconfig`), RiskWarn},
	{regexp.MustCompile(`update-alternatives`), RiskWarn},
}

// classifyScriptContent classifies the content of a script.
func classifyScriptContent(content string) ScriptRisk {
	risk := RiskSafe
	for _, p := range riskPatterns {
		if p.re.MatchString(content) {
			if p.risk == RiskBlock {
				return RiskBlock
			}
			risk = RiskWarn
		}
	}
	return risk
}

// findUnits finds systemd units created by a package.
func findUnits(pkg string) []string {
	files, err := dpkgListFiles(pkg)
	if err != nil {
		return nil
	}
	var units []string
	for _, f := range files {
		if strings.HasSuffix(f, ".service") ||
			strings.HasSuffix(f, ".socket") ||
			strings.HasSuffix(f, ".timer") {
			units = append(units, f)
		}
	}
	return units
}

func runCmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	return string(out), err
}

func runCmdIn(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd.Run()
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// PackageInfo is used for inspect JSON.
type PackageInfo struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Files     []string   `json:"files,omitempty"`
	Scripts   []string   `json:"scripts,omitempty"`
	Units     []string   `json:"units,omitempty"`
	Risk      ScriptRisk `json:"risk"`
	InspectAt time.Time  `json:"inspect_at"`
}

// InspectJSON returns inspect information as JSON.
func (m *Manager) InspectJSON(pkg string) (*PackageInfo, error) {
	info := &PackageInfo{
		Name:      pkg,
		InspectAt: time.Now(),
		Risk:      RiskSafe,
	}

	dpkgInfo, _ := runCmdOutput("dpkg", "-s", pkg)
	for _, line := range strings.Split(dpkgInfo, "\n") {
		if strings.HasPrefix(line, "Version: ") {
			info.Version = strings.TrimPrefix(line, "Version: ")
		}
	}

	info.Files, _ = dpkgListFiles(pkg)
	info.Units = findUnits(pkg)

	scripts := []string{"preinst", "postinst", "prerm", "postrm"}
	for _, s := range scripts {
		path := filepath.Join("/var/lib/dpkg/info", pkg+"."+s)
		if _, err := os.Stat(path); err == nil {
			info.Scripts = append(info.Scripts, s)
			if r := classifyScript(path); r > info.Risk {
				info.Risk = r
			}
		}
	}

	return info, nil
}

// MarshalJSON for ScriptRisk (already a string, no override needed).
var _ = json.Marshal
