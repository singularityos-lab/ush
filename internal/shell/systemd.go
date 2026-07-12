// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// systemd.go starts and manages systemd --user inside the guest.
package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// SystemdConfig describes the configuration of systemd --user in the guest.
type SystemdConfig struct {
	RuntimeDir string // /run/user/<uid>
	UID        int
	StorageDir string
}

// SystemdManager manages the lifecycle of systemd --user in the guest.
type SystemdManager struct {
	cfg  *SystemdConfig
	cmd  *exec.Cmd
	done chan struct{}
}

// NewSystemdManager creates a new manager.
func NewSystemdManager(cfg *SystemdConfig) *SystemdManager {
	return &SystemdManager{
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

// Start starts systemd --user in the guest.
func (sm *SystemdManager) Start() error {
	// On de-systemd hosts (e.g. Sinty, sinit as PID1) there is no system systemd,
	// so systemd --user has no manager to attach to: it execs, exits early, and
	// wastes the readiness timeout on a doomed launch. Gate on the system
	// manager's private socket /run/systemd/private, not the /run/systemd/system
	// directory: sinit lists that directory as a unit search path (and other
	// tools can mkdir it) so its mere existence is not proof of a live manager,
	// whereas the private socket is created only by a running systemd PID1.
	// bindRunSystemd bind-mounts host /run/systemd (recursively) into the guest
	// only when the host has it, so the socket's absence here is a reliable
	// sd_booted() proxy, so return a clean no-op instead.
	if _, err := os.Stat("/run/systemd/private"); err != nil {
		ushlog.Info("systemd: no system manager (/run/systemd/private absent), skipping systemd --user")
		return nil
	}

	if err := sm.prepareEnvironment(); err != nil {
		return fmt.Errorf("systemd: prepare env: %w", err)
	}

	systemdPath, err := findSystemd()
	if err != nil {
		ushlog.Warn("systemd: not found, skipping systemd --user startup", "err", err)
		return nil
	}

	ushlog.Info("systemd: starting systemd --user", "path", systemdPath)

	sm.cmd = exec.Command(systemdPath, "--user")
	sm.cmd.Env = sm.buildEnv()
	sm.cmd.Stdout = io.Discard
	sm.cmd.Stderr = io.Discard
	if os.Getenv("USH_VERBOSE") != "" {
		// In verbose mode, log systemd --user output to a temp file for inspection.
		logPath := "/tmp/ush-systemd.log"
		if f, err := os.Create(logPath); err == nil {
			sm.cmd.Stderr = f
			sm.cmd.Stdout = f
		}
	}
	sm.cmd.SysProcAttr = systemdProcAttr()

	if err := sm.cmd.Start(); err != nil {
		return fmt.Errorf("systemd: startup failed: %w", err)
	}

	ushlog.Info("systemd: started", "pid", sm.cmd.Process.Pid)

	// Wait for systemd to become ready (max 10 seconds).
	go func() {
		sm.cmd.Wait()
		close(sm.done)
	}()

	if err := sm.waitReady(10 * time.Second); err != nil {
		ushlog.Warn("systemd: not ready within timeout", "err", err)
		// Non-fatal: continue anyway.
	}

	return nil
}

// Stop stops systemd --user.
func (sm *SystemdManager) Stop() {
	if sm.cmd == nil || sm.cmd.Process == nil {
		return
	}

	// Send SIGTERM first, then SIGKILL after timeout.
	sm.cmd.Process.Signal(os.Signal(sigterm()))
	select {
	case <-sm.done:
	case <-time.After(5 * time.Second):
		sm.cmd.Process.Kill()
	}
}

// prepareEnvironment prepares the directories needed by systemd --user.
func (sm *SystemdManager) prepareEnvironment() error {
	uid := strconv.Itoa(sm.cfg.UID)

	dirs := []string{
		sm.cfg.RuntimeDir,
		filepath.Join(sm.cfg.RuntimeDir, "systemd"),
		filepath.Join(sm.cfg.RuntimeDir, "systemd", "units"),
		"/run/user",
		"/run/user/" + uid,
		filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user"),
		filepath.Join(os.Getenv("HOME"), ".local", "share", "systemd", "user"),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			ushlog.Warn("systemd: mkdir failed", "dir", d, "err", err)
		}
	}

	// Ensure /etc/machine-id exists (required by systemd).
	machineIDPath := "/etc/machine-id"
	if _, err := os.Stat(machineIDPath); os.IsNotExist(err) {
		if err := writeMachineID(machineIDPath); err != nil {
			ushlog.Warn("systemd: unable to create machine-id", "err", err)
		}
	}

	return nil
}

// buildEnv constructs the environment for systemd --user inside the guest.
func (sm *SystemdManager) buildEnv() []string {
	uid := strconv.Itoa(sm.cfg.UID)
	// Do NOT pass the host DBUS_SESSION_BUS_ADDRESS - systemd --user must
	// create its own bus socket at $XDG_RUNTIME_DIR/bus.
	return []string{
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
		"LOGNAME=" + os.Getenv("USER"),
		"XDG_RUNTIME_DIR=/run/user/" + uid,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SYSTEMD_COLORS=0",
	}
}

// waitReady waits for systemd --user to become operational.
func (sm *SystemdManager) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Check if systemd died early.
		select {
		case <-sm.done:
			return fmt.Errorf("systemd exited early")
		default:
		}

		// Check if systemd responds via systemctl --user.
		cmd := exec.Command("systemctl", "--user", "is-system-running")
		cmd.Env = sm.buildEnv()
		out, err := cmd.Output()
		if err == nil {
			state := string(out)
			if state == "running\n" || state == "degraded\n" {
				ushlog.Info("systemd: ready", "state", state)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout")
}

// findSystemd searches for systemd in the guest PATH.
func findSystemd() (string, error) {
	candidates := []string{
		"/usr/lib/systemd/systemd",
		"/lib/systemd/systemd",
		"/usr/sbin/init",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("systemd not found")
}

// writeMachineID generates and writes a machine-id in the guest.
func writeMachineID(path string) error {
	// Generate a simple UUID as machine-id.
	id := fmt.Sprintf("%032x\n", time.Now().UnixNano())
	return os.WriteFile(path, []byte(id), 0444)
}
