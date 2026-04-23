// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package shell implements the ush interactive shell.
// Uses mvdan.cc/sh/v3 as a POSIX+bash-compatible parser/runner and adds
// readline, job control, tab completion and ush-specific builtins.
package shell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/singularityos-lab/ush/internal/broker"
	"github.com/singularityos-lab/ush/internal/compat"
	"github.com/singularityos-lab/ush/internal/jail"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/pkg"
)

// Shell is the main ush shell.
type Shell struct {
	runner    *interp.Runner
	parser    *syntax.Parser
	pkgMgr    *pkg.Manager
	sessionID string
	histFile  string
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
}

// Config describes the shell configuration options.
type Config struct {
	PkgManager *pkg.Manager
	SessionID  string
	StorageDir string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

// New creates a new shell instance.
func New(cfg *Config) (*Shell, error) {
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	sh := &Shell{
		pkgMgr:    cfg.PkgManager,
		sessionID: cfg.SessionID,
		histFile:  filepath.Join(cfg.StorageDir, "shell_history"),
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
	}

	sh.parser = syntax.NewParser(
		syntax.Variant(syntax.LangBash),
		syntax.KeepComments(false),
	)

	runner, err := interp.New(
		interp.StdIO(stdin, stdout, stderr),
		interp.ExecHandlers(sh.execHandler),
		interp.OpenHandler(openHandler),
	)
	if err != nil {
		return nil, fmt.Errorf("shell: init runner: %w", err)
	}

	sh.runner = runner
	return sh, nil
}

// RunInteractive starts the shell in interactive mode with readline.
func (sh *Shell) RunInteractive(ctx context.Context) error {
	rl, err := newReadline(sh.histFile, sh.completionFunc())
	if err != nil {
		return fmt.Errorf("shell: init readline: %w", err)
	}
	defer rl.Close()

	// job-control signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGTSTP)
	defer signal.Stop(sigCh)

	for {
		line, err := rl.Readline(sh.prompt())
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(sh.stdout, "exit")
				return nil
			}
			if isInterrupt(err) {
				fmt.Fprintln(sh.stdout)
				continue
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := sh.RunLine(ctx, line); err != nil {
			if isExitError(err) || errors.Is(err, errShellRestart) {
				return nil
			}
			fmt.Fprintf(sh.stderr, "USH: %v\n", err)
		}
	}
}

// RunLine executes a single command line.
func (sh *Shell) RunLine(ctx context.Context, line string) error {
	f, err := sh.parser.Parse(strings.NewReader(line), "")
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	return sh.runner.Run(ctx, f)
}

// RunScript executes a script from a reader.
func (sh *Shell) RunScript(ctx context.Context, r io.Reader, name string) error {
	f, err := sh.parser.Parse(r, name)
	if err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	return sh.runner.Run(ctx, f)
}

// execHandler intercepts commands before execution.
// Handles ush builtins (pkg, perm), blocks direct apt/dpkg,
// redirects bare systemctl to systemctl --user, and adapts
// Electron/Chromium apps for the user namespace.
func (sh *Shell) execHandler(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 {
			return next(ctx, args)
		}

		cmd := filepath.Base(args[0])

		// no running apt/dpkg by hand
		switch cmd {
		case "apt", "apt-get", "apt-cache", "apt-mark", "dpkg", "dpkg-reconfigure":
			hc := interp.HandlerCtx(ctx)
			fmt.Fprintf(hc.Stderr, "USH: '%s' is not available directly.\nuse 'pkg' to manage packages.\n", cmd)
			return interp.NewExitStatus(127)
		}

		// Redirect bare `systemctl` to `systemctl --user` unless the caller
		// already passed --system or --user explicitly.
		if cmd == "systemctl" {
			hasScope := false
			for _, a := range args[1:] {
				if a == "--user" || a == "--system" || a == "--global" {
					hasScope = true
					break
				}
			}
			if !hasScope {
				newArgs := make([]string, 0, len(args)+1)
				newArgs = append(newArgs, args[0], "--user")
				newArgs = append(newArgs, args[1:]...)
				args = newArgs
			}
		}

		// Builtin pkg.
		if cmd == "pkg" {
			return sh.builtinPkg(ctx, args[1:])
		}

		// Builtin perm: request a permission via the host broker.
		if cmd == "perm" {
			return sh.builtinPerm(ctx, args[1:])
		}

		// Builtin run: launch an app inside a per-app execution sandbox.
		if cmd == "run" {
			return sh.builtinRun(ctx, args[1:])
		}

		// Builtin restart: tear down this session and start a fresh ush, so
		// changes that only apply at startup (e.g. `perm trust-dir`) take effect.
		if cmd == "restart" {
			return sh.builtinRestart(ctx)
		}

		// Builtin dsh: switch this session to the developer world. Gated by a
		// host-side broker confirmation, so sandboxed code cannot escalate itself.
		if cmd == "dsh" {
			return sh.builtinDsh(ctx)
		}

		// Singularity Guard builtins (thin clients for the singd daemon).
		if cmd == "scan" {
			return sh.builtinScan(ctx, args[1:])
		}
		if cmd == "guard" {
			return sh.builtinGuard(ctx, args[1:])
		}
		if cmd == "quarantine" {
			return sh.builtinQuarantine(ctx, args[1:])
		}

		if cmd == "code" {
			args = adaptVSCodeArgs(args)
		}

		if cmd == "git" {
			return execGitWithNamespaceIdentity(ctx, args)
		}

		return next(ctx, args)
	}
}

func execGitWithNamespaceIdentity(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	path, err := interp.LookPathDir(hc.Dir, hc.Env, args[0])
	if err != nil {
		fmt.Fprintln(hc.Stderr, err)
		return interp.NewExitStatus(127)
	}

	cmd := exec.CommandContext(ctx, path, args[1:]...)
	cmd.Dir = hc.Dir
	cmd.Stdin = hc.Stdin
	cmd.Stdout = hc.Stdout
	cmd.Stderr = hc.Stderr
	cmd.Env = envWithOverrides(hc.Env, map[string]string{
		"USH_PRELOAD_IDENTITY": "root",
	})

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return interp.NewExitStatus(uint8(exitErr.ExitCode()))
		}
		fmt.Fprintln(hc.Stderr, err)
		return interp.NewExitStatus(127)
	}
	return nil
}

func envWithOverrides(env expand.Environ, overrides map[string]string) []string {
	values := make(map[string]string)
	env.Each(func(name string, vr expand.Variable) bool {
		if !vr.Exported || !vr.Set || vr.Kind != expand.String {
			return true
		}
		values[name] = vr.Str
		return true
	})
	for name, value := range overrides {
		values[name] = value
	}

	keys := make([]string, 0, len(values))
	for name := range values {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, name := range keys {
		out = append(out, name+"="+values[name])
	}
	return out
}
