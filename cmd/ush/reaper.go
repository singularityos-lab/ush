// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/singularityos-lab/ush/internal/config"
	ushlog "github.com/singularityos-lab/ush/internal/log"
)

const (
	guestShellArg   = "--guest-shell"
	envGuestPreload = "USH_GUEST_PRELOAD"
)

type guestExit int

func (e guestExit) Error() string {
	return fmt.Sprintf("guest shell exited with status %d", int(e))
}

func superviseGuestShell(logLevel string) error {
	cmd := exec.Command("/proc/self/exe", guestShellArg, logLevel)
	cmd.Args[0] = os.Args[0]
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = guestShellEnv(os.Environ())
	return superviseChild(cmd)
}

func superviseChild(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("guest shell: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			cmd.Process.Signal(sig)
		}
	}()

	shellPid := cmd.Process.Pid
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("guest shell: %w", err)
		}
		if pid != shellPid {
			continue
		}
		switch {
		case ws.Exited():
			if code := ws.ExitStatus(); code != 0 {
				return guestExit(code)
			}
			return nil
		case ws.Signaled():
			return guestExit(128 + int(ws.Signal()))
		}
	}
}

func guestShellEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "LD_PRELOAD="); ok {
			out = append(out, envGuestPreload+"="+v)
			continue
		}
		out = append(out, e)
	}
	return out
}

func runGuestShellMain(logLevel string) int {
	ushlog.Init(logLevel, nil)
	if v, ok := os.LookupEnv(envGuestPreload); ok {
		os.Unsetenv(envGuestPreload)
		os.Setenv("LD_PRELOAD", v)
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ush: config: %v\n", err)
		return 1
	}
	storageDir := os.Getenv("USH_STORAGE_DIR")
	defer applyGuestLayers(cfg, os.Getenv("HOME"), hostRuntimeDir(), storageDir)()
	if err := runGuestShell(storageDir, os.Getenv("USH_SESSION_ID"), os.Getenv("HOME")); err != nil {
		fmt.Fprintf(os.Stderr, "ush: %v\n", err)
		return 1
	}
	return 0
}
