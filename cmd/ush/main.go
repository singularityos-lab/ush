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
	var scriptFile string
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
		default:
			// Login-shell semantics: the first non-flag argument is a script file
			// to run (`ush script.sh`). Ignored when -c is given.
			if scriptFile == "" && !strings.HasPrefix(args[i], "-") {
				scriptFile = args[i]
			}
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

	// Propagate the requested run-mode to the child via env (the child re-execs
	// and reads these back inside the namespaces).
	if cmdFlag != "" {
		os.Setenv("USH_CMD", cmdFlag)
	} else if scriptFile != "" {
		// Read the script on the host side and hand its contents to the guest:
		// the guest pivot_roots into its own filesystem, so a host path (e.g.
		// /tmp/x.sh) would not resolve inside it. The whole script still runs
		// through the sandboxed POSIX interpreter.
		data, rerr := os.ReadFile(scriptFile)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "ush: cannot read script %s: %v\n", scriptFile, rerr)
			os.Exit(1)
		}
		os.Setenv("USH_CMD", string(data))
	} else if stdinIsTTY() {
		// Interactive session: if the kernel lacks Landlock, say so loudly once,
		// otherwise the weakened containment boundary is silent.
		security.WarnIfLandlockUnavailable(os.Stderr)
	}

	// Parent phase: prepare and launch child in namespaces.
	return runParent(cfg)
}

// stdinIsTTY reports whether standard input is a terminal. A false result means
// ush was fed a script on stdin (pipe/redirect) and must run non-interactively.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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

// runParent prepares the namespaces and re-launches the process in the guest.
func runParent(cfg *config.Config) error {
	// make sure the storage dirs exist
	if err := os.MkdirAll(cfg.StorageDir, 0700); err != nil {
		return fmt.Errorf("storage dir: %w", err)
	}

	// Bootstrap apt/dpkg if not present on the host system.
	// Must happen before entering the namespace (network is available).
	if err := tools.EnsureApt(); err != nil {
		fmt.Fprintf(os.Stderr, "ush: apt bootstrap failed, pkg install will not work: %v\n", err)
	}

	// Inject the tools path into the child.
	os.Setenv("USH_TOOLS_DIR", tools.ToolsDir())
	if cwd, err := os.Getwd(); err == nil {
		os.Setenv("USH_START_CWD", cwd)
	}

	// Create a new session.
	sessMgr := session.NewManager(cfg.StorageDir)
	sess, err := sessMgr.New(false)
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}

	ushlog.Info("ush: starting session",
		"id", sess.ID,
		"version", config.AppVersion,
	)

	// Decide the network backend.
	//   "builtin": isolated guest netns with NO pasta; the supervisor services
	//              egress by injecting host-connected fds (no external TCP/IP
	//              stack dependency, and the connect TOCTOU is closed).
	//   else (pasta): isolated netns bridged by pasta; falls back to the shared
	//              host network only if pasta is missing.
	enableNet := cfg.EnableNetNamespace
	builtinNet := false
	if enableNet {
		if cfg.NetworkBackend == "builtin" {
			builtinNet = true
			ushlog.Info("ush: built-in networking (isolated netns, supervisor-serviced egress)")
		} else {
			pastaAvailable := false
			for _, p := range []string{"/usr/bin/pasta", "/usr/sbin/pasta", "/bin/pasta"} {
				if _, err := os.Stat(p); err == nil {
					pastaAvailable = true
					break
				}
			}
			if !pastaAvailable {
				ushlog.Warn("ush: pasta not found, net namespace disabled (guest will use host network)")
				enableNet = false
			}
		}
	}

	// Configure namespaces.
	nsCfg := &ns.Config{
		EnablePID: cfg.EnablePIDNamespace,
		EnableNet: enableNet,
		EnableIPC: true,
		EnableUTS: true,
		HostUID:   os.Getuid(),
		HostGID:   os.Getgid(),
	}

	// Developer (dsh) profile: map a subordinate id range into the guest so
	// nested rootless containers (podman/distrobox) have ids to work with.
	devProfile := os.Getenv("USH_PROFILE") == "dev"
	if devProfile {
		nsCfg.EnableCgroupNS = true // /sys/fs/cgroup rooted at the delegated scope
		// dsh shares the host network namespace: nested containers need a real,
		// routable stack (DNS, registries, their own networking), and the builtin
		// fd-injection model only services single connect()s. dsh is not a boundary.
		nsCfg.EnableNet = false
		enableNet = false
		builtinNet = false
		if u, err := user.Current(); err == nil {
			if s, c, ok := ns.LookupSubID("/etc/subuid", u.Username, u.Uid); ok {
				nsCfg.UseSubuid = true
				nsCfg.SubUIDStart, nsCfg.SubUIDCount = s, c
			}
			if s, c, ok := ns.LookupSubID("/etc/subgid", u.Username, u.Uid); ok {
				nsCfg.SubGIDStart, nsCfg.SubGIDCount = s, c
			}
		}
		if !nsCfg.UseSubuid || nsCfg.SubGIDCount == 0 {
			nsCfg.UseSubuid = false
			ushlog.Warn("dsh: no /etc/subuid or /etc/subgid range for this user; nested containers will not work")
		} else {
			ushlog.Info("dsh: developer profile with subordinate id range",
				"subuid", fmt.Sprintf("%d+%d", nsCfg.SubUIDStart, nsCfg.SubUIDCount))
		}
	}

	// Inject the session ID into the child environment.
	os.Setenv("USH_SESSION_ID", sess.ID)
	os.Setenv("USH_STORAGE_DIR", cfg.StorageDir)
	os.Setenv("USH_LOG_LEVEL", cfg.LogLevel)
	os.Setenv("USH_HOST_UID", strconv.Itoa(os.Getuid()))
	os.Setenv("USH_HOST_GID", strconv.Itoa(os.Getgid()))
	// Pin the host runtime dir ONCE, from the real host session, and hand it to
	// the guest via the environment. Every later hostRuntimeDir() call (parent
	// supervisor bind AND guest-side dial/mount-helper) then agrees on the same
	// path regardless of any XDG_RUNTIME_DIR reset after the userns reexec.
	os.Setenv("USH_HOST_RUNTIME_DIR", hostRuntimeDir())

	// Read host motd before pivot_root so it's available inside the guest.
	if motd, err := os.ReadFile("/etc/ush/motd"); err == nil {
		os.Setenv("USH_MOTD", string(motd))
	}

	// Start seccomp-notify supervisor: listen on a Unix socket in
	// XDG_RUNTIME_DIR (bind-mounted into the guest) for the notif fd sent
	// by the child after it installs its notify filter.
	var supervisor *security.Supervisor
	{
		xdgRuntime := hostRuntimeDir()
		// The seccomp socket (and the restart/dsh sentinels) live in the ush subdir,
		// which is bind-mounted into the guest. Create it here on the host so the
		// supervisor can bind its listener before the child dials.
		_ = os.MkdirAll(filepath.Join(xdgRuntime, "ush"), 0o700)
		sockPath := security.NotifSocketName(xdgRuntime, sess.ID)
		os.Setenv("USH_NOTIF_SOCK", sockPath)
		// Restart channel: the `restart` builtin drops this sentinel (the ush
		// runtime dir is bind-mounted into the guest) and the parent re-execs.
		os.Setenv("USH_RESTART_FILE", filepath.Join(xdgRuntime, "ush", "restart-"+sess.ID))
		// Become-dsh channel: the `dsh` builtin drops this (after broker confirm)
		// and the parent re-execs into the developer profile.
		os.Setenv("USH_DSH_FILE", filepath.Join(xdgRuntime, "ush", "become-dsh-"+sess.ID))

		notifCh := make(chan int, 1)
		go func() {
			fd, err := security.RecvNotifFd(sockPath)
			if err != nil {
				ushlog.Warn("security: failed to receive notif fd", "err", err)
				close(notifCh)
				return
			}
			notifCh <- fd
		}()

		// Start supervisor goroutine once we get the notif fd.
		// IMPORTANT: supervisor.Run() must start before doing any blocking D-Bus
		// calls, because the child may already be blocked on an execve notification.
		go func() {
			fd, ok := <-notifCh
			if !ok {
				return
			}
			supervisor = security.NewSupervisor(fd, nil)
			// Tell the supervisor whether the guest has its own net namespace
			// (pasta active). When it does NOT, loopback is the host's and must
			// be mediated/denied rather than exempted.
			supervisor.SetNetnsIsolated(enableNet)
			// Built-in networking: service egress via fd injection (no pasta).
			supervisor.SetBuiltinNet(builtinNet)
			// Permission UX: simple (per-app prompts) by default, fine on request.
			supervisor.SetSimplePermissions(cfg.PermissionMode != "fine")
			// Developer (dsh) profile: the supervisor audits but does not enforce,
			// so it never fights the nested container runtime. dsh is a dev world,
			// not a boundary against the code you run there.
			if devProfile {
				supervisor.SetDevMode(true)
			}
			// Keep host-backed shares non-executable: nothing the guest writes to
			// a real host directory may ever be run by the host. Computed from the
			// same rules the guest FS uses (data dirs + :rw extra binds, minus the
			// active dev cwd).
			if hd, err := os.UserHomeDir(); err == nil {
				paths := (&fs.GuestFS{HomeDir: hd, ExtraBinds: cfg.ExtraBindMounts}).HostBackedRWGuestPaths()
				supervisor.SetExecStripPrefixes(paths)
				ushlog.Info("security: exec-strip active on host-backed shares", "prefixes", len(paths))
			}
			// User-trusted developer dirs are exempt: full host access on purpose.
			trustedDirs := loadTrustedDevDirs(cfg.StorageDir)
			supervisor.SetTrustedDevDirs(trustedDirs)
			if len(trustedDirs) > 0 {
				ushlog.Info("security: trusted developer dirs exempt from exec-strip", "count", len(trustedDirs))
			}
			// Forward behavioural telemetry to the Singularity Guard daemon
			// (singd). Best-effort: drops events if singd is not running.
			supervisor.SetEventSink(guardsink.New(sess.ID))
			// Start handling notifications immediately (child may be blocked on execve).
			go supervisor.Run()
			// Ensure the broker is running, then attach the client. Prefer the
			// systemd user unit when a user manager is present; otherwise spawn the
			// binary directly so ush is self-sufficient on de-systemd hosts too. The
			// broker binds a private AF_UNIX socket, so poll until it appears.
			if !broker.IsAvailable() {
				if err := exec.Command("systemctl", "--user", "start", "ush-broker").Run(); err != nil || !broker.IsAvailable() {
					startBrokerDirect()
				}
				for i := 0; i < 20 && !broker.IsAvailable(); i++ {
					time.Sleep(100 * time.Millisecond)
				}
			}
			if broker.IsAvailable() {
				if bc, err := broker.NewClient(sess.ID); err == nil {
					supervisor.SetBrokerClient(bc)
					ushlog.Info("security: supervisor broker connected - sensitive syscalls require approval")
				}
			} else {
				ushlog.Warn("security: broker unavailable - supervisor running in audit-only mode")
			}
		}()
	}

	// Reexec in the namespace.
	cmd, err := ns.Reexec(nsCfg)
	if err != nil {
		sessMgr.SetStopped(sess.ID)
		return fmt.Errorf("namespace: %w", err)
	}

	sessMgr.SetRunning(sess.ID)

	// dsh: delegate cgroup v2 controllers from the HOST side. The guest cannot do
	// it: in its cgroup namespace the parent (host-side) process in the same scope
	// shows up as pid 0 and is unmovable, so the scope root never empties and
	// controllers stay disabled. Here we see every real pid, move them into a
	// leaf, and enable the controllers so nested rootless podman/crun can use them.
	if devProfile {
		hostCgroupDance()
	}

	// Start pasta from the PARENT (host net namespace) pointing at the child's
	// network namespace. Pasta must NOT run inside the new empty net namespace.
	// In built-in mode there is no pasta: the supervisor services egress itself.
	if enableNet && !builtinNet {
		go startPastaForChild(cfg, cmd.Process.Pid)
	}

	// Intercept signals and propagate them to the child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				cmd.Process.Signal(sig)
			}
		}
	}()

	// Resource guard: a runaway backstop, not a throttle. It only kills the
	// guest when it exhausts system memory (the thing that freezes a machine);
	// CPU is reported for context but a busy CPU is healthy and never kills.
	rguard := resourceguard.New(resourceguard.Config{
		PID:              cmd.Process.Pid,
		CheckInterval:    3 * time.Second,
		CPUPercentMax:    100,
		MemoryPercentMax: 100,
	})
	rguard.Start()

	err = cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)
	rguard.Stop()

	if supervisor != nil {
		supervisor.Stop()
	}

	sessMgr.SetStopped(sess.ID)

	// If the guest asked to become dsh (developer world, broker-confirmed),
	// re-exec into the dev profile in place. On success this does not return.
	if df := os.Getenv("USH_DSH_FILE"); df != "" {
		if _, statErr := os.Stat(df); statErr == nil {
			os.Remove(df)
			ushlog.Info("ush: entering developer shell (dsh)")
			if rerr := reexecSelf("dev"); rerr != nil {
				return fmt.Errorf("dsh: %w", rerr)
			}
		}
	}

	// If the guest asked for a restart, re-exec a fresh session of the SAME
	// profile so startup-only changes (trusted dev dirs, config) take effect.
	if rf := os.Getenv("USH_RESTART_FILE"); rf != "" {
		if _, statErr := os.Stat(rf); statErr == nil {
			os.Remove(rf)
			ushlog.Info("ush: restart requested, re-executing")
			if rerr := reexecSelf(os.Getenv("USH_PROFILE")); rerr != nil {
				return fmt.Errorf("restart: %w", rerr)
			}
		}
	}

	if err != nil {
		if exitErr, ok := err.(*os.PathError); ok {
			ushlog.Debug("ush: child exited", "err", exitErr)
			return nil
		}
		// Non-zero exit status is normal for the shell (Ctrl+D, exit N, etc.)
		return nil
	}

	return nil
}

// reexecSelf replaces the current process with a fresh ush, using the original
// arguments and a cleaned environment (all ush-internal USH_* vars are dropped,
// including the session id and scope marker, so the new run starts a brand-new
// session). profile, when non-empty, pins USH_PROFILE for the new image (so
// "become dsh" and same-profile restart land in the right world). On success it
// does not return.
func reexecSelf(profile string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "USH_") {
			continue
		}
		env = append(env, e)
	}
	if profile != "" {
		env = append(env, "USH_PROFILE="+profile)
	}
	return syscall.Exec(exe, os.Args, env)
}

// loadTrustedDevDirs reads the user-confirmed developer directories from the
// broker's policy file. They are stored under ush storage, outside the guest's
// view, so a compromised guest cannot self-grant. Returns nil if none/unreadable.
// hostRuntimeDir returns the launching user's XDG runtime dir for host-side IPC
// paths (the ush subdir, the seccomp-notify socket, the mount-helper socket).
// In the reexec'd child we run as uid 0 inside the user namespace, so os.Getuid()
// would yield /run/user/0; prefer XDG_RUNTIME_DIR, then USH_HOST_UID captured by
// the parent before the reexec, and only then fall back to os.Getuid().
func hostRuntimeDir() string {
	// USH_HOST_RUNTIME_DIR is the authoritative value the parent computed once
	// (from the real host session) and exported before spawning the guest. It
	// wins over XDG_RUNTIME_DIR, which the guest reexec may reset to the mapped
	// uid's /run/user/0 -- reading that would put the host-side IPC sockets
	// (seccomp supervisor, mount-helper) on a path the parent never binds,
	// re-introducing the uid-mismatch hang the supervisor-socket fix removed.
	if d := os.Getenv("USH_HOST_RUNTIME_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	uid := os.Getuid()
	if h := os.Getenv("USH_HOST_UID"); h != "" {
		if hu, err := strconv.Atoi(h); err == nil {
			uid = hu
		}
	}
	return filepath.Join("/run/user", strconv.Itoa(uid))
}

// startBrokerDirect launches the ush-broker binary as a detached background process.
// It is the fallback for hosts with no systemd user manager (e.g. sinit-based systems),
// where `systemctl --user start` cannot bring the broker up. The broker is looked up on
// PATH first, then next to this executable, so an install that ships both binaries in the
// same directory works without PATH setup.
func startBrokerDirect() {
	path, err := exec.LookPath("ush-broker")
	if err != nil {
		self, e := os.Executable()
		if e != nil {
			return
		}
		path = filepath.Join(filepath.Dir(self), "ush-broker")
	}
	c := exec.Command(path)
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err == nil && c.Process != nil {
		_ = c.Process.Release()
	}
}

func loadTrustedDevDirs(storageDir string) []string {
	eng, err := policy.NewEngine(filepath.Join(storageDir, "policy.json"))
	if err != nil {
		return nil
	}
	var dirs []string
	for _, r := range eng.List() {
		if r.Category == policy.Category("devdir") && r.Decision == policy.DecisionAllow {
			dirs = append(dirs, r.Resource)
		}
	}
	return dirs
}

// runGuestInit is the guest bootstrap (called in the child process inside the namespaces).
func runGuestInit(cfg *config.Config) error {
	sessionID := os.Getenv("USH_SESSION_ID")
	storageDir := os.Getenv("USH_STORAGE_DIR")
	if storageDir == "" {
		storageDir = cfg.StorageDir
	}

	ushlog.Debug("ush guest init", "session", sessionID, "storage", storageDir)

	// Set guest hostname.
	if err := ns.SetHostname("ush-guest"); err != nil {
		ushlog.Warn("ush: failed to set hostname", "err", err)
	}

	// Create a temporary directory for the guest root.
	guestRoot, err := os.MkdirTemp("", "ush-root-*")
	if err != nil {
		return fmt.Errorf("guest root tmpdir: %w", err)
	}

	// Configure the guest filesystem.
	layerMgr := fs.NewLayerManager(storageDir)
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		os.Setenv("HOME", homeDir)
	}
	xdgRuntime := hostRuntimeDir()

	guestFS := &fs.GuestFS{
		GuestRoot:      guestRoot,
		LayerDir:       storageDir + "/layers",
		SessionID:      sessionID,
		HostUID:        0, // inside the user namespace we are already uid 0
		HostGID:        0,
		XDGRuntimeDir:  xdgRuntime,
		HomeDir:        homeDir,
		ToolsDir:       os.Getenv("USH_TOOLS_DIR"),
		ExtraBinds:     cfg.ExtraBindMounts,
		TrustedDevDirs: loadTrustedDevDirs(storageDir),
		DevProfile:     os.Getenv("USH_PROFILE") == "dev",
	}

	// Start the live mount helper BEFORE the guest pivots, while the host
	// filesystem is still visible. It keeps a host-visible mount namespace for
	// the session so `perm trust-dir` / "Share with Linux" can attach a folder
	// into the running guest with no restart. Best-effort.
	if err := mounthelper.Launch(xdgRuntime, sessionID, storageDir); err != nil {
		ushlog.Warn("mount-helper: unavailable, live share disabled (restart still applies)", "err", err)
	}

	if err := guestFS.Setup(); err != nil {
		return fmt.Errorf("filesystem guest: %w", err)
	}
	chdirGuestStart(homeDir, os.Getenv("USH_START_CWD"))

	// dsh: seed a rootless containers config so podman/distrobox work out of the
	// box. The guest /etc is a decoy tmpfs, so /etc/containers is absent; podman
	// checks ~/.config/containers first, so we seed that. Then prepare cgroup v2
	// delegation so crun can create the container cgroups.
	if os.Getenv("USH_PROFILE") == "dev" {
		seedContainersConfig(homeDir)
		seedSubIDDelegation()
	}

	// Inject the LD_PRELOAD shim globally for all guest processes. It makes
	// filesystem operations on RO bind mounts silently succeed (needed by dpkg
	// maintainer scripts) for every process.
	//
	// Identity is left TRUTHFUL by default (USH_PRELOAD_IDENTITY=root, so
	// getuid()/geteuid() report the real namespace UID 0). Faking the UID to the
	// host UID is unsafe as a global default: it desynchronises getuid() from
	// the on-disk owner (every guest file is really UID 0), and apps that verify
	// a path is owned by their own UID then refuse to start. The stat-family
	// wrappers in the shim can keep the lie self-consistent for libc apps, but
	// runtimes that stat via raw syscalls (e.g. Bun, which backs some sandboxed runtimes)
	// bypass libc entirely and would still see the mismatch. GUI apps that need
	// to appear non-root (Electron/Chromium, for the userns sandbox) can opt in
	// per-process with USH_PRELOAD_IDENTITY=host, which the stat wrappers then
	// make consistent.
	// The shim is located in /run/ush/exec/ which is a bind-mount of the host's ush-exec layer.
	shimPath := "/run/ush/exec/ush-chown-shim.so"
	if _, err := os.Stat(shimPath); err != nil {
		ushlog.Warn("ush: LD_PRELOAD shim unavailable", "path", shimPath, "err", err)
	} else if os.Getenv("USH_PROFILE") == "dev" {
		// Dev: do NOT export LD_PRELOAD globally. distrobox/podman forward the
		// shell environment into containers, where /run/ush/exec does not exist,
		// so every command there spams "cannot be preloaded" ld.so errors. The
		// dev guest runs as the real uid (no identity shim needed) and apt/dpkg
		// inject the shim per-command themselves, so a global preload is redundant.
		ushlog.Info("ush: LD_PRELOAD shim not globally injected (dev profile)")
	} else {
		os.Setenv("LD_PRELOAD", shimPath)
		os.Setenv("USH_PRELOAD_IDENTITY", "root")
		ushlog.Info("ush: LD_PRELOAD shim active", "path", shimPath)
	}

	isDev := os.Getenv("USH_PROFILE") == "dev"

	// Apply security layers - after pivot_root so paths refer to guest rootfs.
	// The developer (dsh) profile SKIPS the hard layers: Landlock and the block
	// filter both set NO_NEW_PRIVS, which breaks the setuid newuidmap/newgidmap
	// helpers that nested rootless containers (podman/distrobox) rely on. dsh is
	// a dev environment, not a security boundary against the code you run there;
	// it keeps only the (relaxed) notify filter, installed via the guest's
	// CAP_SYS_ADMIN rather than NO_NEW_PRIVS.
	if !isDev {
		// Layer 2: Landlock filesystem isolation (kernel-enforced, no TOCTOU).
		landlockCfg := security.GuestLandlockConfig(homeDir, xdgRuntime, storageDir)
		if err := security.ApplyLandlock(landlockCfg); err != nil {
			ushlog.Warn("security: Landlock not applied", "err", err)
		}
		// Layer 3: seccomp blocking filter (all threads via TSYNC).
		if err := security.InstallSeccompFilter(); err != nil {
			ushlog.Warn("security: seccomp block filter not installed", "err", err)
		}
	}

	// Layer 3b: seccomp-notify filter. SKIPPED for dsh: it would be audit-only
	// anyway (dsh is not a boundary), and the supervisor servicing nested
	// podman/crun syscalls is pure overhead that can stall the container runtime.
	if !isDev {
		sockPath := os.Getenv("USH_NOTIF_SOCK")
		if sockPath != "" {
			// Step 1: open the connection (no filter yet, connect() is unintercepted).
			notifConn, dialErr := security.DialNotifSocket(sockPath)
			// Step 2: install the filter.
			var notifFd int
			var filterErr error
			{
				notifFd, filterErr = security.InstallSeccompNotifyFilter()
			}
			// Step 3: send fd over already-open connection.
			if dialErr != nil {
				ushlog.Warn("security: cannot dial notif socket (supervisor unavailable)", "err", dialErr)
			} else if filterErr != nil {
				notifConn.Close()
				ushlog.Warn("security: seccomp notify filter not installed", "err", filterErr)
			} else if err := security.SendNotifFdOverConn(notifFd, notifConn); err != nil {
				ushlog.Warn("security: failed to send notif fd to supervisor", "err", err)
			}
		}
	}

	// If in an isolated net namespace, bring up the TAP interface that pasta
	// created from the parent side. Without this, the interface exists but
	// is DOWN and no packets can flow. dsh shares the host network, so skip.
	if cfg.EnableNetNamespace && os.Getenv("USH_PROFILE") != "dev" {
		configureGuestNetwork()
	}

	// Start systemd --user. Skipped for dsh: it fails to become ready without a
	// session bus, costs a startup timeout, and podman uses the cgroupfs manager.
	if cfg.EnablePIDNamespace && !isDev {
		sdCfg := &shell.SystemdConfig{
			RuntimeDir: xdgRuntime,
			UID:        0,
			StorageDir: storageDir,
		}
		sdMgr := shell.NewSystemdManager(sdCfg)
		if err := sdMgr.Start(); err != nil {
			ushlog.Warn("ush: systemd --user not started", "err", err)
		} else {
			// Expose the user bus socket so systemctl --user works.
			os.Setenv("XDG_RUNTIME_DIR", xdgRuntime)
			os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(xdgRuntime, "bus"))
		}
		defer sdMgr.Stop()
	}

	persistent, err := layerMgr.EnsurePersistent()
	if err != nil {
		ushlog.Warn("ush: persistent layer not available", "err", err)
	}
	_ = persistent

	pkgPrefix := layerMgr.PkgRootDir()
	pkgMgr := pkg.New(layerMgr, sessionID, pkgPrefix)

	// Connect broker client to pkg manager if broker is running on host.
	// The guest can reach the host session bus because XDG_RUNTIME_DIR is bind-mounted.
	if broker.IsAvailable() {
		if bc, err := broker.NewClient(sessionID); err == nil {
			pkgMgr.SetBrokerClient(bc)
			ushlog.Info("pkg: broker connected, network access will require user approval")
		} else {
			ushlog.Warn("pkg: broker available but client failed", "err", err)
		}
	}

	// Set environment variables for the guest.
	os.Setenv("SHELL", "/proc/self/exe")
	if homeDir != "" {
		os.Setenv("HOME", homeDir)
	}
	os.Setenv("USH_SESSION_ID", sessionID)
	os.Setenv("PS1", "") // managed by the custom shell

	// Export pkgPrefix into PATH so installed binaries are findable.
	// MUST be before shell.New() because mvdan.cc/sh captures the env
	// at the time the runner is created.
	if pkgPrefix != "" {
		addPkgPrefixToPath(pkgPrefix)
		os.Setenv("USH_PKG_PREFIX", pkgPrefix)
	}

	// Start the shell.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sh, err := shell.New(&shell.Config{
		PkgManager: pkgMgr,
		SessionID:  sessionID,
		StorageDir: storageDir,
	})
	if err != nil {
		return fmt.Errorf("shell: %w", err)
	}

	// -c mode (also script-file mode: the parent reads `ush script.sh` on the
	// host and forwards its contents here): run and exit, no banner.
	if cmd := os.Getenv("USH_CMD"); cmd != "" {
		return sh.RunLine(ctx, cmd)
	}

	// Non-interactive stdin (piped or redirected, e.g. `echo cmd | ush`): read
	// the whole of stdin as a script and exit. Same POSIX interpreter, same
	// sandbox; only a real terminal starts the interactive shell below.
	if !stdinIsTTY() {
		return sh.RunScript(ctx, os.Stdin, "stdin")
	}

	// Show banner.
	printBanner(sessionID)

	if os.Getenv("USH_PROFILE") == "dev" {
		printDshNotice(homeDir)
	} else {
		// Explain the file model once, so "my changes aren't in my real folder"
		// is never a surprise. ush is a shell: the user reads their whole home
		// but writes stay sandboxed until they trust a folder.
		printModelNoticeOnce(homeDir)
	}

	// Start the interactive shell.
	return sh.RunInteractive(ctx)
}

// hostCgroupDance runs on the host (parent) side. It locates our delegated
// systemd scope cgroup, moves every process (parent, guest, and the guest's
// early children, all visible here by real pid) into a leaf, and enables the
// available controllers in the scope's subtree_control. cgroup v2 forbids
// enabling controllers while a cgroup holds processes, so the move must complete
// first; it retries to absorb processes the guest spawns concurrently. After
// this the scope root has controllers and no processes, so the nested container
// runtime can create its own cgroups under it.
func hostCgroupDance() {
	var diag strings.Builder
	defer func() {
		if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
			_ = os.WriteFile(filepath.Join(rt, "ush", "dsh-cgroup.log"), []byte(diag.String()), 0644)
		}
	}()

	selfCg, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		diag.WriteString("read /proc/self/cgroup failed: " + err.Error() + "\n")
		return
	}
	line := strings.TrimSpace(string(selfCg))
	idx := strings.Index(line, "::")
	if idx < 0 {
		diag.WriteString("unexpected cgroup line: " + line + "\n")
		return
	}
	scope := filepath.Join("/sys/fs/cgroup", line[idx+2:])
	leaf := filepath.Join(scope, "init")
	diag.WriteString("scope: " + scope + "\n")

	avail, _ := os.ReadFile(filepath.Join(scope, "cgroup.controllers"))
	availTrim := strings.TrimSpace(string(avail))
	diag.WriteString("controllers available: " + availTrim + "\n")
	var b strings.Builder
	for _, c := range strings.Fields(availTrim) {
		b.WriteString("+" + c + " ")
	}
	ctrls := strings.TrimSpace(b.String())

	if err := os.MkdirAll(leaf, 0755); err != nil {
		diag.WriteString("mkdir init FAILED: " + err.Error() + "\n")
		return
	}

	for attempt := 0; attempt < 10; attempt++ {
		for i := 0; i < 50; i++ {
			data, err := os.ReadFile(filepath.Join(scope, "cgroup.procs"))
			if err != nil {
				diag.WriteString("read cgroup.procs err: " + err.Error() + "\n")
				return
			}
			pids := strings.Fields(string(data))
			if len(pids) == 0 {
				break
			}
			for _, pid := range pids {
				_ = os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(pid+"\n"), 0644)
			}
		}
		if ctrls == "" {
			break
		}
		if werr := os.WriteFile(filepath.Join(scope, "cgroup.subtree_control"), []byte(ctrls), 0644); werr == nil {
			diag.WriteString("subtree_control enabled: " + ctrls + " (attempt " + strconv.Itoa(attempt) + ")\n")
			ushlog.Info("dsh: cgroup controllers delegated for nested containers", "controllers", ctrls)
			return
		} else if attempt == 9 {
			diag.WriteString("subtree_control write FAILED after retries: " + werr.Error() + "\n")
			ushlog.Warn("dsh: could not enable cgroup controllers", "err", werr)
		}
		time.Sleep(80 * time.Millisecond)
	}
}

// seedContainersConfig writes a permissive rootless containers config into the
// dsh home if missing: an image trust policy (accept any image, fine for a dev
// box) and a short-name registry list. Without policy.json podman refuses to
// pull. Only writes files that do not exist, so user edits are kept.
func seedContainersConfig(homeDir string) {
	if homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	if homeDir == "" {
		return
	}
	dir := filepath.Join(homeDir, ".config", "containers")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	policy := filepath.Join(dir, "policy.json")
	if _, err := os.Stat(policy); err != nil {
		_ = os.WriteFile(policy, []byte("{\"default\":[{\"type\":\"insecureAcceptAnything\"}]}\n"), 0644)
	}
	reg := filepath.Join(dir, "registries.conf")
	if _, err := os.Stat(reg); err != nil {
		_ = os.WriteFile(reg, []byte("unqualified-search-registries = [\"docker.io\", \"registry.fedoraproject.org\", \"quay.io\"]\n"), 0644)
	}
	// ush-managed engine config (always rewritten). netns=host: dsh shares the
	// host network, so containers use it directly and rootless netavark (which
	// needs setns into a per-container netns that is not permitted here) is never
	// invoked. cgroupfs manager + file events avoid the systemd/journald (sd-bus)
	// dependency the dsh guest does not have.
	conf := filepath.Join(dir, "containers.conf")
	_ = os.WriteFile(conf, []byte(
		"[containers]\nnetns = \"host\"\n\n"+
			"[engine]\ncgroup_manager = \"cgroupfs\"\nevents_logger = \"file\"\n"), 0644)
	// Force the kernel-native overlay driver with an empty mount_program. The dsh
	// guest holds CAP_SYS_ADMIN in its userns and the mount API is unblocked, so
	// native overlay works; the rootless default (fuse-overlayfs) cannot copy a
	// lower-layer file up on O_RDWR open, which breaks chpasswd/usermod in
	// distrobox ("cannot open /etc/passwd").
	stConf := filepath.Join(dir, "storage.conf")
	_ = os.WriteFile(stConf, []byte(
		"[storage]\ndriver = \"overlay\"\n\n"+
			"[storage.options.overlay]\nmount_program = \"\"\n"), 0644)
}

// seedSubIDDelegation rewrites the guest /etc/subuid and /etc/subgid so nested
// rootless podman/distrobox work. The host entries point at the user's host-level
// subordinate range (e.g. 165536+), but those ids are NOT mapped inside the dsh
// guest user namespace, so newuidmap cannot map a nested container onto them and
// fails with EPERM. We instead delegate the slice of guest ids ABOVE the user's
// own id, all of which the guest userns maps, so the nested map lands on valid
// targets. Range and owner are read from the live id maps, so this is correct
// regardless of the user's real uid.
func seedSubIDDelegation() {
	name := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	write := func(idFile, mapFile string, ownID int) {
		max := maxMappedID(mapFile)
		if max <= ownID {
			return // nothing above the user's id to delegate
		}
		line := fmt.Sprintf("%s:%d:%d\n", name, ownID+1, max-ownID)
		_ = os.WriteFile(idFile, []byte(line), 0644)
	}
	write("/etc/subuid", "/proc/self/uid_map", os.Getuid())
	write("/etc/subgid", "/proc/self/gid_map", os.Getgid())
}

// maxMappedID returns the highest container id mapped in a /proc/<pid>/{uid,gid}_map
// file (container-start + size of the last range), or -1 if it cannot be read.
func maxMappedID(mapFile string) int {
	data, err := os.ReadFile(mapFile)
	if err != nil {
		return -1
	}
	max := -1
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		start, e1 := strconv.Atoi(f[0])
		size, e2 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil {
			continue
		}
		if end := start + size - 1; end > max {
			max = end
		}
	}
	return max
}

// printDshNotice warns, on every dsh start, that it is not a security boundary.
func printDshNotice(homeDir string) {
	fmt.Printf("  \033[1;38;5;202mNOT a security sandbox\033[0m: code you run here has a real dev machine.\n\n")
}

// printModelNoticeOnce explains the write-isolation model on the first
// interactive run only. The marker lives in the persistent guest home, so it
// survives across sessions and is shown exactly once.
func printModelNoticeOnce(homeDir string) {
	if homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	if homeDir == "" {
		return
	}
	marker := filepath.Join(homeDir, ".ush_intro_seen")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	fmt.Printf("\n  \033[33mYour real files are safe by default.\033[0m You can read your whole home, but\n")
	fmt.Printf("  changes are saved inside the sandbox. To work on the real files in a folder,\n")
	fmt.Printf("  run \033[1mperm trust-dir\033[0m there, then \033[1mrestart\033[0m.\n\n")
	_ = os.WriteFile(marker, []byte("1\n"), 0600)
}

func chdirGuestStart(homeDir, startCWD string) {
	startDir := guestStartDir(homeDir, startCWD)
	if startDir == "" {
		startDir = "/"
	}
	if err := os.Chdir(startDir); err == nil {
		return
	}
	if homeDir != "" && startDir != homeDir {
		if err := os.Chdir(homeDir); err == nil {
			return
		}
	}
	if err := os.Chdir("/"); err != nil {
		ushlog.Warn("ush: unable to set guest working directory", "err", err)
	}
}

func guestStartDir(homeDir, startCWD string) string {
	home := filepath.Clean(homeDir)
	if home == "." || home == "/" {
		return "/"
	}

	cwd := filepath.Clean(startCWD)
	if filepath.IsAbs(cwd) {
		if rel, err := filepath.Rel(home, cwd); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return cwd
		}
	}
	return home
}

// configureGuestNetwork brings up the loopback and any TAP interface created by
// pasta in this network namespace. Without this, pasta creates the interface
// but it remains DOWN. We also configure IP/route if pasta hasn't via --config-net.
func configureGuestNetwork() {
	// Always bring up loopback.
	runSilent("ip", "link", "set", "lo", "up")

	// Bring up any non-loopback interface (pasta's TAP).
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		runSilent("ip", "link", "set", name, "up")
		ushlog.Info("ush: network interface up", "iface", name)
	}
}

// runSilent runs a command discarding output (best-effort).
func runSilent(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}

// startPastaForChild starts pasta from the parent (host) network namespace,
// pointing at the child process's network namespace via its PID.
// This is the correct way to use pasta: run it outside the new empty net
// namespace so it can bridge the child's namespace to the host network.
func startPastaForChild(cfg *config.Config, childPID int) {
	pastaPath, err := findInPath([]string{
		"/usr/bin/pasta",
		"/usr/sbin/pasta",
		"/bin/pasta",
	})
	if err != nil {
		ushlog.Warn("ush: pasta not found, network isolation unavailable", "err", err)
		return
	}

	// Give the child a moment to finish namespace setup.
	time.Sleep(200 * time.Millisecond)

	pidStr := strconv.Itoa(childPID)
	cmd := exec.Command(pastaPath,
		"--foreground",
		"--config-net",                         // auto-configure tap interface in the namespace
		"--dns", "1.1.1.1", "--dns", "8.8.8.8", // explicit DNS
		"--ipv4-only", // skip IPv6 (also avoids no-route IPv6 stalls)
		// Forward ports the guest binds back to the host loopback, so services
		// the GUEST starts are reachable from the host, while the guest still
		// cannot see host services (it has its own loopback). This is the
		// asymmetry: host sees into the guest, the guest cannot see the host.
		"-t", "auto",
		"-u", "auto",
		pidStr,
	)
	cmd.Stderr = os.Stderr
	if os.Getenv("USH_VERBOSE") == "" {
		cmd.Stderr = io.Discard
	}
	if err := cmd.Start(); err != nil {
		ushlog.Warn("ush: pasta start failed", "err", err)
		return
	}
	ushlog.Info("ush: pasta network started", "child_pid", childPID)
	// pasta runs until the child exits; we don't need to wait for it here.
}

func findInPath(candidates []string) (string, error) {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func printBanner(sessionID string) {
	w := os.Stdout

	// If the host admin placed a custom motd, print it and stop.
	if motd := strings.TrimSpace(os.Getenv("USH_MOTD")); motd != "" {
		fmt.Fprintf(w, "\n%s\n\n", motd)
		return
	}

	name, color := "ush", "1;34" // blue
	if os.Getenv("USH_PROFILE") == "dev" {
		name, color = "\U0001F527 dsh", "1;38;5;202" // wrench, orange-red
	}
	fmt.Fprintf(w, "\n\033[%sm%s\033[0m  \033[2msession %s\033[0m\n", color, name, sessionID)
	fmt.Fprintf(w, "\033[2m%s\033[0m\n", strings.Repeat("-", 44))
	fmt.Fprintf(w, "  Use \033[1mpkg install <name>\033[0m to install software.\n")
	fmt.Fprintf(w, "  Use \033[1mpkg help\033[0m for the list of pkg commands.\n\n")
}

// addPkgPrefixToPath prepends standard pkgPrefix paths to $PATH and $LD_LIBRARY_PATH.
func addPkgPrefixToPath(prefix string) {
	binPaths := []string{
		filepath.Join(prefix, "usr", "bin"),
		filepath.Join(prefix, "usr", "sbin"),
		filepath.Join(prefix, "usr", "games"),
		filepath.Join(prefix, "bin"),
		filepath.Join(prefix, "sbin"),
	}
	existing := os.Getenv("PATH")
	os.Setenv("PATH", strings.Join(binPaths, ":")+":"+existing)

	libPaths := []string{
		filepath.Join(prefix, "usr", "lib", "x86_64-linux-gnu"),
		filepath.Join(prefix, "usr", "lib"),
		filepath.Join(prefix, "lib", "x86_64-linux-gnu"),
		filepath.Join(prefix, "lib"),
	}
	// Dev: register the pkg-layer libs through /etc/ld.so.conf.d + ldconfig
	// instead of LD_LIBRARY_PATH. The env var is forwarded into distrobox/podman
	// containers, where the guest libs then shadow the container's own (e.g.
	// "libpcre2 no version information available"); a per-root ld.so config does
	// not cross the container boundary. ld.so.conf.d is rebuilt from a writable
	// /etc tmpfs that the guest setup already prepared.
	if os.Getenv("USH_PROFILE") == "dev" {
		var b strings.Builder
		for _, p := range libPaths {
			b.WriteString(p)
			b.WriteByte('\n')
		}
		if err := os.WriteFile("/etc/ld.so.conf.d/00-ush-pkglayer.conf", []byte(b.String()), 0644); err == nil {
			_ = exec.Command("ldconfig").Run()
			return
		}
		// Fall through to the env var if the config could not be written.
	}
	existingLib := os.Getenv("LD_LIBRARY_PATH")
	if existingLib != "" {
		os.Setenv("LD_LIBRARY_PATH", strings.Join(libPaths, ":")+":"+existingLib)
	} else {
		os.Setenv("LD_LIBRARY_PATH", strings.Join(libPaths, ":"))
	}
}
