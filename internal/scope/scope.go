// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package scope relaunches ush inside a transient systemd user scope so the
// whole app (this process and everything it later spawns, including the
// namespaced guest tree) lives in one cgroup. Host task managers then group its
// processes under a single entry, and the resource guard reads exact, kernel-
// accounted CPU and memory from the cgroup. Starting inside a fresh scope (as
// systemd-run and Flatpak do) is the only race-free way: moving our own PID
// after the fact does not capture children reliably. Best-effort: already
// scoped, or no systemd-run / no user bus, means ush runs unscoped.
package scope

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// scopeEnv marks a process that is already running inside our scope, so the
// re-exec happens exactly once.
const scopeEnv = "USH_IN_SCOPE"

// Reexec replaces the current process with systemd-run, which starts ush again
// inside a fresh scope named app-ush-<slug>-<pid>.scope. On success it does not
// return (the new image takes over). It returns nil when already scoped or when
// scoping is unavailable, and a non-nil error only if the exec itself failed;
// in every returning case the caller continues unscoped.
func Reexec(slug string) error {
	if os.Getenv(scopeEnv) == "1" {
		return nil // already inside our scope
	}
	runner, err := exec.LookPath("systemd-run")
	if err != nil {
		return nil // no systemd-run: run unscoped
	}
	// systemd-run --user needs the user bus; without it the exec would replace
	// ush with a doomed systemd-run, so bail out to unscoped instead.
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(xdg, "bus")); err != nil {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil
	}

	unit := fmt.Sprintf("app-ush-%s-%d", sanitize(slug), os.Getpid())
	argv := []string{
		"systemd-run", "--user", "--scope", "--quiet", "--collect",
		"--unit=" + unit,
		"--description=USH app: " + slug,
	}
	if os.Getenv("USH_PROFILE") == "dev" {
		// Delegate the cgroup v2 subtree so nested rootless podman can manage its
		// own container cgroups inside the dsh world.
		argv = append(argv, "--property=Delegate=yes")
	}
	argv = append(argv, "--", self)
	argv = append(argv, os.Args[1:]...)

	env := append(os.Environ(), scopeEnv+"=1")
	// On success this never returns; on failure ush keeps running unscoped.
	return syscall.Exec(runner, argv, env)
}

// sanitize reduces an app name to characters allowed in a systemd unit name,
// so slugs like "code" or "google-chrome" stay readable.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "app"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
