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

func adaptVSCodeArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	for _, a := range args[1:] {
		switch a {
		case "tunnel", "serve-web":
			return args
		}
	}

	out := append([]string{}, args...)
	if !hasArgPrefix(out[1:], "--no-sandbox") {
		out = append(out, "--no-sandbox")
	}
	if !hasArgPrefix(out[1:], "--user-data-dir") && !hasArgPrefix(out[1:], "--file-write") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			out = append(out, "--user-data-dir="+filepath.Join(home, ".local", "share", "ush", "vscode-user-data"))
		}
	}
	return out
}

func hasArgPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if a == prefix || strings.HasPrefix(a, prefix+"=") {
			return true
		}
	}
	return false
}

// openHandler handles file opening (passthrough to host for now).
func openHandler(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
	return interp.DefaultOpenHandler()(ctx, path, flag, perm)
}

// prompt builds the shell prompt.
func (sh *Shell) prompt() string {
	cwd := ""
	if sh.runner != nil {
		cwd = sh.runner.Dir
	}
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		} else {
			cwd = "?"
		}
	}

	// shorten $HOME to ~
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(cwd, home) {
		cwd = "~" + cwd[len(home):]
	}

	user := os.Getenv("USER")
	if user == "" {
		user = "guest"
	}

	host, hostColor := "USH", "1;34" // blue
	if os.Getenv("USH_PROFILE") == "dev" {
		host, hostColor = "\U0001F527DSH", "1;38;5;202" // wrench, orange-red
	}
	return fmt.Sprintf("\033[1;32m%s\033[0m@\033[%sm%s\033[0m:\033[1;36m%s\033[0m$ ", user, hostColor, host, cwd)
}

// completionFunc returns the completion function for readline.
func (sh *Shell) completionFunc() CompletionFunc {
	return func(line string, pos int) (head string, completions []string, tail string) {
		// Determine the word being completed: everything from the last space to cursor.
		prefix := line[:pos]
		lastSpace := strings.LastIndex(prefix, " ")
		var word string
		if lastSpace == -1 {
			word = prefix
		} else {
			word = prefix[lastSpace+1:]
		}

		// Command completion (no space before cursor = first word).
		if lastSpace == -1 {
			completions = append(completions, completeCommands(word)...)
			completions = append(completions, completeBuiltinCmds(word)...)
			return line[:pos-len(word)], completions, line[pos:]
		}

		// First word determines context.
		firstWord := strings.Fields(prefix)[0]

		// pkg subcommand completion.
		if firstWord == "pkg" {
			fields := strings.Fields(prefix)
			if len(fields) == 1 {
				// "pkg " with trailing space: complete subcommands from empty.
				completions = completePkgSubcommands(word)
				return line[:pos-len(word)], completions, line[pos:]
			}
			if len(fields) == 2 && word != "" {
				completions = completePkgSubcommands(word)
				if len(completions) > 0 {
					return line[:pos-len(word)], completions, line[pos:]
				}
			}
			// After pkg subcommand, complete file paths.
			completions = completeFiles(word)
			return line[:pos-len(word)], completions, line[pos:]
		}

		// perm category completion.
		if firstWord == "perm" {
			fields := strings.Fields(prefix)
			if len(fields) == 1 {
				completions = completePermCategories(word)
				return line[:pos-len(word)], completions, line[pos:]
			}
			if len(fields) == 2 && word != "" {
				completions = completePermCategories(word)
				if len(completions) > 0 {
					return line[:pos-len(word)], completions, line[pos:]
				}
			}
		}

		// File/path completion.
		completions = completeFiles(word)
		return line[:pos-len(word)], completions, line[pos:]
	}
}

// builtinPkg handles the pkg command as a builtin.
func (sh *Shell) builtinPkg(ctx context.Context, args []string) error {
	if sh.pkgMgr == nil {
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintln(hc.Stderr, "pkg: manager not available")
		return interp.NewExitStatus(1)
	}

	if len(args) == 0 {
		hc := interp.HandlerCtx(ctx)
		printPkgUsage(hc.Stdout)
		return nil
	}

	hc := interp.HandlerCtx(ctx)

	switch args[0] {
	case "install", "i":
		return sh.pkgMgr.Install(ctx, hc.Stdout, hc.Stderr, args[1:])
	case "update":
		return sh.pkgMgr.Update(ctx, hc.Stdout, hc.Stderr)
	case "remove", "rm":
		return sh.pkgMgr.Remove(ctx, hc.Stdout, hc.Stderr, args[1:])
	case "fix":
		return sh.pkgFix(ctx, hc, args[1:])
	case "burn":
		return sh.pkgMgr.Burn(ctx, hc.Stdout, hc.Stderr, args[1:])
	case "diff":
		return sh.pkgMgr.Diff(ctx, hc.Stdout)
	case "inspect":
		if len(args) < 2 {
			fmt.Fprintln(hc.Stderr, "pkg inspect: specify a package")
			return interp.NewExitStatus(1)
		}
		return sh.pkgMgr.Inspect(ctx, hc.Stdout, hc.Stderr, args[1])
	case "freeze":
		return sh.pkgMgr.Freeze(ctx, hc.Stdout)
	case "list", "ls":
		return sh.pkgMgr.List(ctx, hc.Stdout)
	case "compat":
		return sh.pkgCompat(ctx, hc, args[1:])
	case "help", "--help", "-h":
		printPkgUsage(hc.Stdout)
		return nil
	default:
		fmt.Fprintf(hc.Stderr, "pkg: unknown command '%s'. Use 'pkg help'.\n", args[0])
		return interp.NewExitStatus(1)
	}
}

// resolveAppExe turns a user-supplied app name or path into the absolute,
// symlink-resolved executable path. App trust is keyed on this so it matches
// the kernel-reported /proc/<pid>/exe the supervisor checks, which the guest
// cannot spoof (unlike the comm name). A bare name is looked up on PATH; an
// absolute/relative path is used directly.
// errShellRestart breaks the interactive loop so the guest exits and the parent
// re-execs a fresh ush. It is recognized in RunInteractive.
var errShellRestart = errors.New("ush: restart requested")

// builtinRestart requests a full ush restart: it drops a sentinel file that the
// host-side parent checks after the guest exits, then breaks the shell loop so
// the guest tears down. The parent re-execs a clean ush, applying any startup-only
// changes (trusted dev dirs, config, extra binds). The sentinel lives in the ush
// runtime dir, the only host-shared writable surface, so no privileged path is
// touched.
func (sh *Shell) builtinRestart(ctx context.Context) error {
	hc := interp.HandlerCtx(ctx)
	rf := os.Getenv("USH_RESTART_FILE")
	if rf == "" {
		fmt.Fprintln(hc.Stderr, "restart: not supported in this session")
		return interp.NewExitStatus(1)
	}
	if err := os.MkdirAll(filepath.Dir(rf), 0700); err != nil {
		fmt.Fprintf(hc.Stderr, "restart: %v\n", err)
		return interp.NewExitStatus(1)
	}
	if err := os.WriteFile(rf, []byte("1\n"), 0600); err != nil {
		fmt.Fprintf(hc.Stderr, "restart: %v\n", err)
		return interp.NewExitStatus(1)
	}
	fmt.Fprintln(hc.Stdout, "Restarting ush...")
	return errShellRestart
}

// builtinDsh switches the session to the developer world (dsh). It asks the
// broker for host-side confirmation; on approval it drops the become-dsh
// sentinel and breaks the shell loop, and the parent re-execs into the dev
// profile (replace, same terminal). A guest process can trigger the dialog but
// cannot confirm it, so it is not an escalation path for sandboxed code.
func (sh *Shell) builtinDsh(ctx context.Context) error {
	hc := interp.HandlerCtx(ctx)
	if os.Getenv("USH_PROFILE") == "dev" {
		fmt.Fprintln(hc.Stdout, "Already in the developer shell (dsh).")
		return nil
	}
	df := os.Getenv("USH_DSH_FILE")
	if df == "" {
		fmt.Fprintln(hc.Stderr, "dsh: not supported in this session")
		return interp.NewExitStatus(1)
	}
	if !broker.IsAvailable() {
		fmt.Fprintln(hc.Stderr, "dsh: broker not available")
		return interp.NewExitStatus(1)
	}
	client, err := broker.NewClient(sh.sessionID)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "dsh: %v\n", err)
		return interp.NewExitStatus(1)
	}
	defer client.Close()
	if !client.RequestDevShell() {
		// Declined at the dialog, or refused by policy (disabled by the device
		// image, or not enabled). The broker is the authority; we cannot tell the
		// cases apart from here, so point at the host-side enable path.
		fmt.Fprintln(hc.Stderr, "dsh: unavailable (not confirmed, or disabled/not enabled by policy)")
		fmt.Fprintln(hc.Stderr, "     if it is just disabled, on the host run:  ush dsh enable")
		return interp.NewExitStatus(1)
	}
	if err := os.WriteFile(df, []byte("1\n"), 0600); err != nil {
		fmt.Fprintf(hc.Stderr, "dsh: %v\n", err)
		return interp.NewExitStatus(1)
	}
	fmt.Fprintln(hc.Stdout, "Entering developer shell (dsh)...")
	return errShellRestart
}
