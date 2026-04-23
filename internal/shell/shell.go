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

// resolveDirArg turns a user-supplied directory argument (empty means the current
// working directory) into a cleaned absolute path.
func resolveDirArg(dir string) (string, error) {
	if dir == "" {
		return os.Getwd()
	}
	if !filepath.IsAbs(dir) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(cwd, dir)
	}
	return filepath.Clean(dir), nil
}

func resolveAppExe(name string) (string, error) {
	var p string
	if strings.ContainsRune(name, '/') {
		p = name
	} else {
		found, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("%q not found on PATH (give a full path)", name)
		}
		p = found
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}

// builtinRun launches an app inside a per-app execution sandbox (jail): a fresh
// mount namespace with the system tree read-only, a private home and /tmp, and
// only the host paths the app's profile grants. Default-deny: an unprofiled app
// sees nothing of the guest home (other apps' data, credentials).
//
// Profiles live at ~/.config/ush/apps/<name>.json. The persistent per-app home
// is ~/.ush-apps/<name>, inside the (already isolated) guest home.
func (sh *Shell) builtinRun(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)
	if len(args) == 0 {
		fmt.Fprintln(hc.Stderr, "usage: run <app> [args...]   (per-app sandbox; profile in ~/.config/ush/apps/<app>.json)")
		return interp.NewExitStatus(2)
	}

	appPath, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(hc.Stderr, "run: %s: executable not found\n", args[0])
		return interp.NewExitStatus(127)
	}
	name := filepath.Base(args[0])
	profJSON := loadJailProfile(name)

	home := os.Getenv("HOME")
	appHome := filepath.Join(home, ".ush-apps", name)
	_ = os.MkdirAll(appHome, 0700)

	// /proc/self/exe always resolves to the running ush binary, even after the
	// guest pivot_root (os.Executable() would return the now-invalid host path).
	cmdArgs := append([]string{jail.Sentinel, appPath}, args[1:]...)
	c := exec.CommandContext(ctx, "/proc/self/exe", cmdArgs...)
	c.Env = append(os.Environ(),
		jail.EnvProfile+"="+profJSON,
		jail.EnvAppHome+"="+appHome,
	)
	c.Stdin = hc.Stdin
	c.Stdout = hc.Stdout
	c.Stderr = hc.Stderr
	// A fresh mount namespace for the jail; pivot_root happens inside it.
	c.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}

	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return interp.NewExitStatus(uint8(ee.ExitCode()))
		}
		fmt.Fprintf(hc.Stderr, "run: %v\n", err)
		return interp.NewExitStatus(1)
	}
	return nil
}

// loadJailProfile returns the JSON profile for an app, or a minimal default
// (default-deny: no extra grants) when none is configured.
func loadJailProfile(name string) string {
	path := filepath.Join(os.Getenv("HOME"), ".config", "ush", "apps", name+".json")
	if data, err := os.ReadFile(path); err == nil {
		var probe map[string]interface{}
		if json.Unmarshal(data, &probe) == nil {
			return string(data)
		}
	}
	return `{"name":"` + name + `"}`
}

// builtinPerm handles the 'perm' builtin: requests a permission via the broker.
// Usage: perm <category> <resource> [reason]
func (sh *Shell) builtinPerm(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(args) == 0 {
		fmt.Fprintln(hc.Stderr, "usage: perm <category> <resource> [reason]")
		fmt.Fprintln(hc.Stderr, "       perm trust <app>        (allow all permissions for app)")
		fmt.Fprintln(hc.Stderr, "       perm untrust <app>      (revoke blanket permission for app)")
		fmt.Fprintln(hc.Stderr, "       perm trust-dir [path]   (full host access for a dev dir: build/run/git)")
		fmt.Fprintln(hc.Stderr, "       perm untrust-dir [path] (revoke a dev dir's trust)")
		fmt.Fprintln(hc.Stderr, "       perm list-dirs          (list trusted dev dirs)")
		fmt.Fprintln(hc.Stderr, "  categories: network, filesystem, device, service")
		return interp.NewExitStatus(1)
	}

	if !broker.IsAvailable() {
		fmt.Fprintln(hc.Stderr, "perm: broker not available (USH-broker not running?)")
		return interp.NewExitStatus(1)
	}

	client, err := broker.NewClient(sh.sessionID)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "perm: broker connect: %v\n", err)
		return interp.NewExitStatus(1)
	}
	defer client.Close()

	// perm trust <app>
	if args[0] == "trust" {
		if len(args) < 2 {
			fmt.Fprintln(hc.Stderr, "perm trust: specify an application name or path")
			return interp.NewExitStatus(1)
		}
		exe, err := resolveAppExe(args[1])
		if err != nil {
			fmt.Fprintf(hc.Stderr, "perm trust: %v\n", err)
			return interp.NewExitStatus(1)
		}
		if err := client.AllowApp(exe); err != nil {
			fmt.Fprintf(hc.Stderr, "perm trust: %v\n", err)
			return interp.NewExitStatus(1)
		}
		fmt.Fprintf(hc.Stdout, "perm: %s is now trusted (all permissions allowed)\n", exe)
		return nil
	}

	// perm untrust <app>
	if args[0] == "untrust" {
		if len(args) < 2 {
			fmt.Fprintln(hc.Stderr, "perm untrust: specify an application name or path")
			return interp.NewExitStatus(1)
		}
		exe, err := resolveAppExe(args[1])
		if err != nil {
			fmt.Fprintf(hc.Stderr, "perm untrust: %v\n", err)
			return interp.NewExitStatus(1)
		}
		if err := client.DenyApp(exe); err != nil {
			fmt.Fprintf(hc.Stderr, "perm untrust: %v\n", err)
			return interp.NewExitStatus(1)
		}
		fmt.Fprintf(hc.Stdout, "perm: %s is no longer trusted\n", exe)
		return nil
	}

	// perm trust-dir [path] / perm untrust-dir [path]
	if args[0] == "trust-dir" || args[0] == "untrust-dir" {
		dir := ""
		if len(args) >= 2 {
			dir = args[1]
		}
		abs, err := resolveDirArg(dir)
		if err != nil {
			fmt.Fprintf(hc.Stderr, "perm %s: %v\n", args[0], err)
			return interp.NewExitStatus(1)
		}
		if args[0] == "trust-dir" {
			if err := client.TrustDir(abs); err != nil {
				fmt.Fprintf(hc.Stderr, "perm trust-dir: %v\n", err)
				return interp.NewExitStatus(1)
			}
			fmt.Fprintf(hc.Stdout, "perm: %s is now a trusted dev dir (full host access: build, run, git).\n", abs)
			fmt.Fprintln(hc.Stdout, "      Applied live to this session - cd into it. (If it doesn't update, run 'restart'.)")
			return nil
		}
		if err := client.UntrustDir(abs); err != nil {
			fmt.Fprintf(hc.Stderr, "perm untrust-dir: %v\n", err)
			return interp.NewExitStatus(1)
		}
		fmt.Fprintf(hc.Stdout, "perm: %s is no longer a trusted dev dir. Restart ush to apply.\n", abs)
		return nil
	}

	// perm list-dirs
	if args[0] == "list-dirs" {
		fmt.Fprintln(hc.Stdout, client.ListDevDirs())
		return nil
	}

	if len(args) < 2 {
		fmt.Fprintln(hc.Stderr, "usage: perm <category> <resource> [reason]")
		return interp.NewExitStatus(1)
	}

	category := args[0]
	resource := args[1]
	reason := ""
	if len(args) >= 3 {
		reason = strings.Join(args[2:], " ")
	}

	decision, err := client.RequestPermission(category, resource, reason)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "perm: request failed: %v\n", err)
		return interp.NewExitStatus(1)
	}

	fmt.Fprintf(hc.Stdout, "perm: decision=%s\n", decision)

	if decision == broker.DecisionDeny {
		return interp.NewExitStatus(1)
	}
	return nil
}

// pkgFix implements 'pkg fix [--broken]'.
func (sh *Shell) pkgFix(ctx context.Context, hc interp.HandlerContext, args []string) error {
	broken := false
	for _, a := range args {
		if a == "--broken" || a == "-b" {
			broken = true
		}
	}

	if broken {
		return sh.pkgMgr.FixBroken(ctx, hc.Stdout, hc.Stderr)
	}
	return sh.pkgMgr.Fix(ctx, hc.Stdout, hc.Stderr)
}

func printPkgUsage(w io.Writer) {
	fmt.Fprint(w, `pkg - USH package runtime

USAGE:
  pkg install [--one-time] <package...>   install package(s)
  pkg remove <package...>                 remove package(s) from layer
  pkg fix [--broken]                      repair broken dpkg state / dependencies
  pkg burn <package...>                   destroy package layer
  pkg diff                                show delta from base system
  pkg inspect <package>                   show files, scripts, units, side effects
  pkg freeze                              promote ephemeral layer to persistent
  pkg list                                list installed packages
  pkg compat [<package>]                  check package compatibility with USH
`)
}

// completeBuiltinCmds completes ush builtin commands (pkg, perm).
func completeBuiltinCmds(prefix string) []string {
	var matches []string
	for _, cmd := range []string{"pkg", "perm", "scan", "guard", "quarantine"} {
		if strings.HasPrefix(cmd, prefix) {
			matches = append(matches, cmd)
		}
	}
	return matches
}
