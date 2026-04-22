// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package shell

import (
	"context"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/interp"

	"github.com/singularityos-lab/ush/internal/guardclient"
	"github.com/singularityos-lab/ush/internal/security"
)

// builtinScan implements `scan <path>`, an on-demand antivirus scan, served
// by the Singularity Guard daemon (singd).
func (sh *Shell) builtinScan(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) == 0 {
		fmt.Fprintln(hc.Stderr, "usage: scan <path> [path...]")
		return interp.NewExitStatus(2)
	}
	resp, err := guardclient.Do("scan", args...)
	if err == guardclient.ErrUnavailable {
		fmt.Fprintln(hc.Stderr, "scan: Singularity Guard (singd) is not running.")
		return interp.NewExitStatus(69) // EX_UNAVAILABLE
	}
	if err != nil {
		fmt.Fprintf(hc.Stderr, "scan: %v\n", err)
		return interp.NewExitStatus(1)
	}
	if resp.Output != "" {
		fmt.Fprintln(hc.Stdout, strings.TrimRight(resp.Output, "\n"))
	}
	if !resp.OK {
		if resp.Error != "" {
			fmt.Fprintf(hc.Stderr, "scan: %s\n", resp.Error)
		}
		return interp.NewExitStatus(1)
	}
	return nil
}

// builtinQuarantine implements `quarantine list` and `quarantine restore <id>`.
func (sh *Shell) builtinQuarantine(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) == 0 {
		args = []string{"list"}
	}
	resp, err := guardclient.Do("quarantine", args...)
	if err == guardclient.ErrUnavailable {
		fmt.Fprintln(hc.Stderr, "quarantine: Singularity Guard (singd) is not running.")
		return interp.NewExitStatus(69)
	}
	if err != nil {
		fmt.Fprintf(hc.Stderr, "quarantine: %v\n", err)
		return interp.NewExitStatus(1)
	}
	if resp.Output != "" {
		fmt.Fprintln(hc.Stdout, strings.TrimRight(resp.Output, "\n"))
	}
	if !resp.OK {
		return interp.NewExitStatus(1)
	}
	return nil
}

// builtinGuard implements `guard status`, a summary of the local security
// posture. It always reports the locally-knowable Landlock status (so the user
// learns immediately if the kernel lacks Landlock), then appends singd's view
// when the daemon is reachable.
func (sh *Shell) builtinGuard(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}

	switch sub {
	case "status":
		abi, ok := security.LandlockStatus()
		if ok {
			fmt.Fprintf(hc.Stdout, "Landlock:   active (ABI v%d)\n", abi)
		} else {
			fmt.Fprintln(hc.Stdout, "Landlock:   UNAVAILABLE, kernel lacks CONFIG_SECURITY_LANDLOCK")
		}

		if !guardclient.Available() {
			fmt.Fprintln(hc.Stdout, "singd:      not running")
			return nil
		}
		resp, err := guardclient.Do("status", args[1:]...)
		if err != nil {
			fmt.Fprintf(hc.Stdout, "singd:      error (%v)\n", err)
			return nil
		}
		if resp.Output != "" {
			fmt.Fprintln(hc.Stdout, strings.TrimRight(resp.Output, "\n"))
		}
		return nil
	case "help", "--help", "-h":
		fmt.Fprintln(hc.Stdout, "usage: guard status")
		return nil
	default:
		fmt.Fprintf(hc.Stderr, "guard: unknown subcommand %q (try 'guard status')\n", sub)
		return interp.NewExitStatus(2)
	}
}
