// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package jail implements the per-app execution sandbox (the second
// confinement layer, INSIDE the ush guest). When the user runs an app via the
// shell `run` builtin, ush re-executes itself in a fresh mount namespace and
// jail.RunChild builds a minimal, per-app root: the system tree (/usr, /lib,
// ...) read-only, a PRIVATE home and /tmp, and ONLY the extra paths the app's
// profile explicitly grants. Everything else in the guest home (other apps'
// data, credentials) is invisible: default-deny.
//
// This is execution-time confinement, not install-time: the same binary can run
// under different profiles depending on context. This layer covers the
// filesystem jail; network/device/secrets stay mediated by the broker, and
// per-app seccomp tailoring is not yet applied.
package jail

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/security"
	"golang.org/x/sys/unix"
)

// Env keys passed from the `run` builtin to the re-executed jail child.
const (
	EnvProfile = "USH_JAIL_PROFILE"  // JSON-encoded Profile
	EnvAppHome = "USH_JAIL_APP_HOME" // persistent per-app home dir (host/guest path)
	Sentinel   = "__ush_jail__"      // argv[1] marker for the jail child
)

// Profile is the per-app filesystem grant. Default-deny: an app sees the system
// tree, a private home and /tmp, plus exactly the paths listed here.
type Profile struct {
	Name string   `json:"name"`
	RW   []string `json:"rw"` // absolute guest paths bound read-write into the jail
	RO   []string `json:"ro"` // absolute guest paths bound read-only
	// Net controls networking: "shared" lets the app use the guest network
	// (still broker-mediated); anything else (default) denies it via seccomp
	// (no AF_INET/AF_INET6 sockets).
	Net string `json:"net"`
}

// IsChild reports whether the current process is a jail child (re-executed by
// the `run` builtin).
func IsChild() bool {
	return len(os.Args) > 1 && os.Args[1] == Sentinel
}

// systemRO are the read-only system directories every jail needs to run a
// dynamically-linked binary. They are bound from the guest root.
var systemRO = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"}

// RunChild is the entry point inside the jail child. The process is already in
// a fresh mount namespace (the builtin set CLONE_NEWNS). It builds the jail
// root, pivots into it, and execs the requested command (os.Args[2:]).
func RunChild() error {
	cmd := os.Args[2:]
	if len(cmd) == 0 {
		return fmt.Errorf("jail: no command")
	}

	var prof Profile
	if raw := os.Getenv(EnvProfile); raw != "" {
		_ = json.Unmarshal([]byte(raw), &prof)
	}
	home := os.Getenv("HOME")
	appHome := os.Getenv(EnvAppHome)

	if err := setupRoot(prof, home, appHome); err != nil {
		return fmt.Errorf("jail: setup: %w", err)
	}

	// Per-app seccomp: baseline hardening always, plus network denial unless the
	// profile grants "shared" networking. Applied to this process and inherited
	// across the exec below.
	_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err := security.InstallJailSeccomp(prof.Net == "shared"); err != nil {
		ushlog.Warn("jail: seccomp not installed", "err", err)
	}

	// Clear the jail wiring from the environment before handing off. Also drop
	// the dpkg LD_PRELOAD shim: it lives at /run/ush/exec (not bound into the
	// jail) and is only needed by apt/dpkg, so it would just spam ld.so warnings.
	os.Unsetenv(EnvProfile)
	os.Unsetenv(EnvAppHome)
	os.Unsetenv("LD_PRELOAD")

	path, err := lookPath(cmd[0])
	if err != nil {
		return fmt.Errorf("jail: %q: %w", cmd[0], err)
	}
	if err := syscall.Exec(path, cmd, os.Environ()); err != nil {
		return fmt.Errorf("jail: exec %s: %w", path, err)
	}
	return nil
}

func setupRoot(prof Profile, home, appHome string) error {
	// Private propagation so nothing we do leaks back to the guest mount ns.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make-rprivate: %w", err)
	}

	// Fresh tmpfs to assemble the new root in (the guest /run is a tmpfs).
	newRoot := "/run/ush-jail-root"
	if err := os.MkdirAll(newRoot, 0755); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", newRoot, "tmpfs", 0, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs newroot: %w", err)
	}

	mkdir := func(p string) { _ = os.MkdirAll(filepath.Join(newRoot, p), 0755) }
	for _, d := range []string{"proc", "dev", "tmp", "run", "var", "home", filepath.Dir(home)} {
		mkdir(d)
	}

	// System tree, read-only.
	for _, d := range systemRO {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		mkdir(strings.TrimPrefix(d, "/"))
		if err := bind(d, filepath.Join(newRoot, d), true); err != nil {
			ushlog.Warn("jail: system bind failed", "dir", d, "err", err)
		}
	}

	// /proc and /dev from the guest (this jail does not create a new pid namespace).
	_ = bind("/proc", filepath.Join(newRoot, "proc"), false)
	_ = bind("/dev", filepath.Join(newRoot, "dev"), false)

	// Private /tmp.
	_ = unix.Mount("tmpfs", filepath.Join(newRoot, "tmp"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777")

	// Private home: a per-app persistent dir if given, else an empty tmpfs.
	homeDst := filepath.Join(newRoot, home)
	_ = os.MkdirAll(homeDst, 0700)
	if appHome != "" {
		_ = os.MkdirAll(appHome, 0700)
		if err := bind(appHome, homeDst, false); err != nil {
			ushlog.Warn("jail: app home bind failed", "err", err)
		}
	} else {
		_ = unix.Mount("tmpfs", homeDst, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0700")
	}

	// Profile grants (bound from the guest root, still fully visible pre-pivot).
	for _, p := range prof.RO {
		bindInto(newRoot, p, true)
	}
	for _, p := range prof.RW {
		bindInto(newRoot, p, false)
	}

	// pivot_root into the new tree.
	oldRoot := filepath.Join(newRoot, ".oldroot")
	_ = os.MkdirAll(oldRoot, 0700)
	if err := unix.PivotRoot(newRoot, oldRoot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	// Detach the old root so the jail cannot reach back into the guest tree.
	if err := unix.Unmount("/.oldroot", unix.MNT_DETACH); err != nil {
		ushlog.Warn("jail: detach oldroot failed", "err", err)
	}
	_ = os.Remove("/.oldroot")
	return nil
}

// bindInto binds a guest path to the same path inside newRoot, creating the
// target (file or dir). Used for profile grants.
func bindInto(newRoot, src string, ro bool) {
	fi, err := os.Stat(src)
	if err != nil {
		return
	}
	dst := filepath.Join(newRoot, src)
	if fi.IsDir() {
		_ = os.MkdirAll(dst, 0755)
	} else {
		_ = os.MkdirAll(filepath.Dir(dst), 0755)
		if f, e := os.OpenFile(dst, os.O_CREATE, 0644); e == nil {
			f.Close()
		}
	}
	if err := bind(src, dst, ro); err != nil {
		ushlog.Warn("jail: profile bind failed", "src", src, "ro", ro, "err", err)
	}
}

func bind(src, dst string, ro bool) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	if ro {
		_ = unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
	}
	return nil
}

// lookPath resolves a command against PATH (the jail sees the system PATH).
func lookPath(cmd string) (string, error) {
	if strings.Contains(cmd, "/") {
		return cmd, nil
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, cmd)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found in PATH")
}
