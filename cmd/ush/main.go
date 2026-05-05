// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// ush - shell orchestrator for the Linux application runtime.
//
// Execution flow:
//
//  1. Normal invocation (parent phase):
//     - Load configuration
//     - Create session
//     - Re-execute itself with Linux namespaces (reexec)
//     - Wait for the child process to finish
//
//  2. Re-execution (child phase, ENV USH_NS_INIT=1):
//     - Set up guest filesystem (overlay + bind mount)
//     - Pivot root
//     - Start systemd --user
//     - Start the interactive shell
//     - Cleanup on exit
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"os/exec"

	"github.com/singularityos-lab/ush/internal/broker"
	"github.com/singularityos-lab/ush/internal/config"
	"github.com/singularityos-lab/ush/internal/devpolicy"
	"github.com/singularityos-lab/ush/internal/fs"
	"github.com/singularityos-lab/ush/internal/guardsink"
	"github.com/singularityos-lab/ush/internal/jail"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/mounthelper"
	"github.com/singularityos-lab/ush/internal/ns"
	"github.com/singularityos-lab/ush/internal/pkg"
	"github.com/singularityos-lab/ush/internal/policy"
	"github.com/singularityos-lab/ush/internal/resourceguard"
	"github.com/singularityos-lab/ush/internal/scope"
	"github.com/singularityos-lab/ush/internal/security"
	"github.com/singularityos-lab/ush/internal/session"
	"github.com/singularityos-lab/ush/internal/shell"
	"github.com/singularityos-lab/ush/internal/tools"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ush: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Developer userns stub: the first exec after an unmapped clone(CLONE_NEWUSER)
	// for dsh. It runs without capabilities and only waits for the parent to write
	// our subordinate id map, then re-execs the real guest init (mapped, with
	// capabilities). Must be the very first thing, before any privileged work.
	if ns.IsUsernsStub() {
		return ns.RunUsernsStub()
	}

	// Live mount helper: a child of the guest init that injects trusted-dir
	// binds into the running guest. Must short-circuit before any other logic.
	if mounthelper.IsHelper() {
		return mounthelper.Run()
	}

	// Per-app jail child: re-executed by the shell `run` builtin in a fresh
	// mount namespace. Build the per-app root and exec the command. This must
	// run before any namespace/config logic.
	if jail.IsChild() {
		return jail.RunChild()
	}

	// Resolve the profile (secure "user" ush vs developer "dev" dsh) and pin it
	// in the env: the re-exec into namespaces uses the real binary path and would
	// otherwise lose argv0 ("dsh"). Children and helpers inherit it.
	if os.Getenv("USH_PROFILE") == "" {
		if filepath.Base(os.Args[0]) == "dsh" {
			os.Setenv("USH_PROFILE", "dev")
		} else {
			os.Setenv("USH_PROFILE", "user")
		}
	}

	// minimal flag parse, before we touch the config
	// -c "cmd" -> run non-interactively and exit.
	// -v / --verbose -> enable INFO-level logs (default is WARN).
	var cmdFlag string
	verbose := false
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c":
			if i+1 < len(args) {
				cmdFlag = args[i+1]
				i++
			}
		case "-v", "--verbose":
			verbose = true
		}
	}

	// pass -v down to the child
	if verbose {
		os.Setenv("USH_VERBOSE", "1")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// dsh admin: enable / disable / status the developer shell. Handled here,
	// before any namespace work, since it is just a policy toggle.
	if sub := dshAdminSub(); sub != "" {
		return runDshAdmin(sub, cfg.StorageDir)
	}

	// Quiet by default: only errors. -v (or log_level in config) brings back the
	// operational warnings/info. The Landlock notice is a direct print, so it is
	// shown regardless.
	logLevel := "error"
	if verbose {
		logLevel = cfg.LogLevel
		if logLevel == "" {
			logLevel = "info"
		}
	} else if cfg.LogLevel != "" {
		logLevel = cfg.LogLevel
	}
	ushlog.Init(logLevel, nil)

	// Child process: already inside namespaces, set up and launch guest.
	if ns.IsChildProcess() {
		return runGuestInit(cfg)
	}

	// Gate the developer shell. It must be permitted by the image/managed policy
	// and enabled by the user. The host-side parent enforces it (the child is
	// already past the gate); the image policy lives in the immutable rootfs, so
	// a guest cannot forge it.
	if os.Getenv("USH_PROFILE") == "dev" {
		switch devpolicy.Evaluate(cfg.StorageDir) {
		case devpolicy.DenyForbidden:
			fmt.Fprintln(os.Stderr, "dsh: developer shell is disabled by device policy")
			os.Exit(1)
		case devpolicy.DenyNotEnabled:
			fmt.Fprintln(os.Stderr, "dsh: developer shell is not enabled.")
			fmt.Fprintln(os.Stderr, "     enable it with:  ush dsh enable")
			os.Exit(1)
		}
	}

	// Relaunch the whole ush app inside a per-app systemd user scope, so the
	// host groups its processes under one cgroup (and the resource guard reads
	// kernel-accounted usage). On success this re-execs and does not return;
	// otherwise ush simply runs unscoped.
	if err := scope.Reexec(appSlug(cmdFlag)); err != nil {
		ushlog.Info("scope: running unscoped: " + err.Error())
	}

	// Propagate -c to child via env.
	if cmdFlag != "" {
		os.Setenv("USH_CMD", cmdFlag)
	} else {
		// Interactive session: if the kernel lacks Landlock, say so loudly once,
		// otherwise the weakened containment boundary is silent.
		security.WarnIfLandlockUnavailable(os.Stderr)
	}

	// Parent phase: prepare and launch child in namespaces.
	return runParent(cfg)
}

// appSlug derives a short app name for the scope unit from the -c command
// (its first word's basename), defaulting to "shell" for an interactive run.
func appSlug(cmdFlag string) string {
	if cmdFlag == "" {
		return "shell"
	}
	fields := strings.Fields(cmdFlag)
	if len(fields) == 0 {
		return "shell"
	}
	return filepath.Base(fields[0])
}

// dshAdminSub returns the dsh admin subcommand ("enable" / "disable" / "status")
// if the invocation is `ush dsh <sub>` or `dsh <sub>`, else "".
func dshAdminSub() string {
	isSub := func(s string) bool { return s == "enable" || s == "disable" || s == "status" }
	a := os.Args
	if filepath.Base(a[0]) == "dsh" && len(a) >= 2 && isSub(a[1]) {
		return a[1]
	}
	if len(a) >= 3 && a[1] == "dsh" && isSub(a[2]) {
		return a[2]
	}
	return ""
}

// runDshAdmin toggles or reports the developer-shell opt-in. Enabling is refused
// when the image/managed policy forbids dsh.
func runDshAdmin(sub, storageDir string) error {
	switch sub {
	case "status":
		pol, enabled := devpolicy.Status(storageDir)
		fmt.Printf("policy:  %s\n", pol)
		fmt.Printf("enabled: %v\n", enabled)
	case "enable":
		if err := devpolicy.SetUserEnabled(storageDir, true); err != nil {
			return fmt.Errorf("dsh: %w", err)
		}
		fmt.Println("dsh: developer shell enabled")
	case "disable":
		if err := devpolicy.SetUserEnabled(storageDir, false); err != nil {
			return fmt.Errorf("dsh: %w", err)
		}
		fmt.Println("dsh: developer shell disabled")
	}
	return nil
}
