// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package mounthelper injects bind mounts into a RUNNING guest live, so
// `perm trust-dir` / "Share with Linux" take effect without restarting the
// guest and WITHOUT disturbing any running process.
//
// Why a helper is needed: the guest's bind mounts are set up before pivot_root,
// while the host filesystem is still visible and the process holds CAP_SYS_ADMIN
// over the guest mount namespace. After the pivot the guest can no longer see the
// host filesystem, and the unprivileged (rootless) host side has no CAP_SYS_ADMIN
// over the host mount namespace, so it cannot inject a mount either.
//
// The helper is launched BEFORE the pivot, in the guest user namespace, with
// its OWN mount namespace cloned from the still-host-visible
// pre-pivot view (SysProcAttr.Cloneflags = CLONE_NEWNS). It therefore keeps host
// filesystem visibility for the whole session, and because both its own mount
// namespace AND the guest's are owned by the guest user namespace, it holds
// CAP_SYS_ADMIN over both. For each request it clones the host subtree
// (open_tree), enters the guest mount namespace (setns), and attaches the clone
// (move_mount) onto the target. The attach STACKS over the existing write-
// isolated overlay: running processes keep their view, new lookups get the raw
// read-write bind. Nothing is unmounted and nothing is killed.
//
// Security: the helper sees the whole host filesystem in its private namespace,
// so every request is re-validated against the broker's persisted policy
// (devdir entries, which are gated by a host-side confirmation). A request for a
// path that is not an approved trusted dir is refused, so even a guest that
// reached the control socket cannot escalate or leak arbitrary host paths.
package mounthelper

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/policy"
	"golang.org/x/sys/unix"
)

const (
	// EnvHelper marks the re-executed mount-helper process.
	EnvHelper = "USH_MOUNT_HELPER"
	envSock   = "USH_MOUNT_HELPER_SOCK"
	envStore  = "USH_MOUNT_HELPER_STORE"
	// guestMntFd is the inherited fd (ExtraFiles[0] => fd 3) referring to the
	// guest's main mount namespace.
	guestMntFd = 3
)

// SocketPath returns the per-session control socket path inside the ush runtime
// dir (which is bind-mounted into the guest, so both the host broker and the
// guest can reach it; the helper validates every request against policy).
func SocketPath(runtimeDir, sessionID string) string {
	return filepath.Join(runtimeDir, "ush", "mount-helper-"+sessionID+".sock")
}

type request struct {
	Path string `json:"path"`
}

type response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// IsHelper reports whether this process should run as the mount helper.
func IsHelper() bool { return os.Getenv(EnvHelper) == "1" }

// Launch starts the mount helper as a child of the guest init, BEFORE the guest
// pivots. It must be called while the host filesystem is still visible. The
// returned process keeps a host-visible mount namespace for the session; it dies
// with the guest pid namespace. Best-effort: on any error live share is simply
// unavailable and the user falls back to `restart`.
func Launch(runtimeDir, sessionID, storageDir string) error {
	sock := SocketPath(runtimeDir, sessionID)
	_ = os.MkdirAll(filepath.Dir(sock), 0700)
	_ = os.Remove(sock)

	// A reference to OUR (the guest init's) mount namespace. It survives the
	// later pivot_root (same namespace object), and the helper re-enters it to
	// attach mounts.
	nsFile, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("open guest mnt ns: %w", err)
	}
	defer nsFile.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		EnvHelper+"=1",
		envSock+"="+sock,
		envStore+"="+storageDir,
	)
	cmd.ExtraFiles = []*os.File{nsFile} // becomes fd 3 in the child
	// Clone a fresh mount namespace at exec time, atomically, from the current
	// (pre-pivot, host-visible) mounts. The child thus keeps host filesystem
	// visibility independently of our upcoming pivot_root.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNS,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start mount helper: %w", err)
	}
	// Reap asynchronously; the helper runs for the session lifetime.
	go func() { _ = cmd.Wait() }()
	ushlog.Info("mount-helper: launched", "pid", cmd.Process.Pid, "sock", sock)
	return nil
}

// Run is the helper entrypoint (in the cloned host-visible mount namespace).
func Run() error {
	// Detach our mounts so nothing we do can propagate back to the guest, and
	// nothing the guest does after pivot propagates to us.
	if err := unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		ushlog.Warn("mount-helper: make-private failed", "err", err)
	}

	sock := os.Getenv(envSock)
	store := os.Getenv(envStore)
	if sock == "" || store == "" {
		return fmt.Errorf("mount-helper: missing env")
	}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("mount-helper: listen %s: %w", sock, err)
	}
	defer ln.Close()
	_ = os.Chmod(sock, 0600)

	h := &helper{storageDir: store}
	ushlog.Info("mount-helper: serving", "sock", sock)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // listener closed
		}
		h.handleConn(conn)
	}
}

type helper struct {
	storageDir string
}

func (h *helper) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req request
	if jerr := json.Unmarshal(line, &req); jerr != nil {
		writeResp(conn, response{Error: "bad request"})
		return
	}
	if err := h.mountOne(req.Path); err != nil {
		ushlog.Warn("mount-helper: mount refused/failed", "path", req.Path, "err", err)
		writeResp(conn, response{Error: err.Error()})
		return
	}
	ushlog.Info("mount-helper: live-mounted trusted dir", "path", req.Path)
	writeResp(conn, response{OK: true})
}

// mountOne validates the path against the persisted policy and, if it is a
// trusted dev dir, attaches a raw read-write clone of it into the guest.
func (h *helper) mountOne(path string) error {
	path = filepath.Clean(strings.TrimRight(path, "/"))
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("invalid path")
	}
	if !h.isTrusted(path) {
		return fmt.Errorf("not an approved trusted directory")
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return injectMount(path, path)
}

// isTrusted re-reads the broker policy and reports whether path is at or below a
// devdir grant (which only the host-confirmed broker can create).
func (h *helper) isTrusted(path string) bool {
	eng, err := policy.NewEngine(filepath.Join(h.storageDir, "policy.json"))
	if err != nil {
		return false
	}
	for _, r := range eng.List() {
		if r.Category != policy.Category("devdir") || r.Decision != policy.DecisionAllow {
			continue
		}
		d := filepath.Clean(strings.TrimRight(r.Resource, "/"))
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// injectMount clones the host subtree at src (visible in our host mount
// namespace) and attaches it at dst inside the guest mount namespace, stacking
// over whatever is mounted there. The namespace-sensitive sequence runs on a
// single dedicated OS thread: we break CLONE_FS sharing so setns() into the
// guest mount namespace is permitted for this thread only, leaving the helper's
// other threads (and their host visibility) untouched. The thread is never
// unlocked, so the Go runtime retires it after the work, discarding its tainted
// namespace.
func injectMount(src, dst string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // deliberately never unlocked

		// Detach this thread's filesystem context so setns(CLONE_NEWNS) is
		// allowed (the kernel refuses it while CLONE_FS is shared with peers).
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			done <- fmt.Errorf("unshare CLONE_FS: %w", err)
			runtime.Goexit()
		}

		// Clone the source subtree while we still see the host filesystem.
		fd, err := unix.OpenTree(unix.AT_FDCWD, src,
			uint(unix.OPEN_TREE_CLONE|unix.AT_RECURSIVE))
		if err != nil {
			done <- fmt.Errorf("open_tree %s: %w", src, err)
			runtime.Goexit()
		}
		defer unix.Close(fd)

		// Enter the guest mount namespace (this thread only).
		if err := unix.Setns(guestMntFd, unix.CLONE_NEWNS); err != nil {
			done <- fmt.Errorf("setns guest mnt: %w", err)
			runtime.Goexit()
		}

		// Attach the clone onto the target, stacking over the overlay. The
		// target dir already exists in the guest (it is exposed write-isolated),
		// so there is a mountpoint to stack on and no running process is moved.
		if err := unix.MoveMount(fd, "", unix.AT_FDCWD, dst,
			unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
			done <- fmt.Errorf("move_mount -> %s: %w", dst, err)
			runtime.Goexit()
		}
		done <- nil
		runtime.Goexit()
	}()
	return <-done
}

func writeResp(conn net.Conn, resp response) {
	data, _ := json.Marshal(resp)
	_, _ = conn.Write(append(data, '\n'))
}

// Notify sends a live-mount request for path to every running session's mount
// helper. Best-effort: helpers that are gone or refuse are ignored. Called by
// the broker right after it persists a directory trust.
func Notify(runtimeDir, path string) {
	pattern := filepath.Join(runtimeDir, "ush", "mount-helper-*.sock")
	socks, _ := filepath.Glob(pattern)
	for _, sock := range socks {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			continue
		}
		data, _ := json.Marshal(request{Path: path})
		_, _ = conn.Write(append(data, '\n'))
		// Best-effort read of the ack, then move on.
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		conn.Close()
	}
}
