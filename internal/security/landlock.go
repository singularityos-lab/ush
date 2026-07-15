// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package security implements Landlock filesystem isolation and seccomp
// syscall filtering for ush guest processes.
package security

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"golang.org/x/sys/unix"
)

// All FS access rights across Landlock ABI v1-v4.
const (
	landlockAccessFSV1 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK

	// V2 adds REFER (hard-links across dirs).
	landlockAccessFSV2 = landlockAccessFSV1 | unix.LANDLOCK_ACCESS_FS_REFER

	// V3 adds TRUNCATE.
	landlockAccessFSV3 = landlockAccessFSV2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE

	// V4 adds IOCTL_DEV.
	landlockAccessFSV4 = landlockAccessFSV3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// readOnlyAccess is the set of access rights granted for read-only paths
// (system directories like /usr, /bin, /lib).
const readOnlyAccess = unix.LANDLOCK_ACCESS_FS_EXECUTE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_DIR

// fullAccess is all access rights - granted for mutable paths like home,
// /tmp, /run, and package layer dirs.
const fullAccess = landlockAccessFSV4

// RulesetAttr matches struct landlock_ruleset_attr.
type RulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64 // ABI v4+
	Scoped           uint32 // ABI v5+
}

// PathBeneathAttr matches struct landlock_path_beneath_attr.
type PathBeneathAttr struct {
	AllowedAccess uint64
	ParentFd      int32
	_             [4]byte // padding
}

// LandlockConfig holds the full policy.
type LandlockConfig struct {
	ROPaths []string // paths allowed read+exec only (no write)
	RWPaths []string // paths allowed full access (read+write+exec)
}

// ApplyLandlock applies Landlock FS isolation to the calling process and all
// its future children. Must be called after pivot_root (so paths refer to the
// guest rootfs). Non-fatal: if the kernel doesn't support Landlock the call
// logs a warning and returns nil.
//
// Landlock applies only to the calling OS thread and processes exec'd
// afterward; LockOSThread pins the goroutine to a stable thread before any
// goroutine can escape.
func ApplyLandlock(cfg LandlockConfig) error {
	// Landlock and NO_NEW_PRIVS apply to the calling thread; pin the goroutine so
	// the scheduler can't move it before the exec. The exec'd shell and its
	// children inherit the restriction.
	runtime.LockOSThread()
	// No UnlockOSThread: stay pinned until exec replaces the process image.

	// Probe ABI version and determine the handled access mask.
	abiVersion, err := probeABI()
	if err != nil {
		ushlog.Warn("security: Landlock not supported by kernel, skipping", "err", err)
		return nil
	}
	ushlog.Info("security: Landlock ABI version", "version", abiVersion)

	handledFS := abiHandledFS(abiVersion)

	attr := RulesetAttr{HandledAccessFS: handledFS}
	rulesetFd, err := landlockCreateRuleset(&attr, uint(unsafe.Sizeof(attr)))
	if err != nil {
		return fmt.Errorf("security: landlock_create_ruleset: %w", err)
	}
	defer unix.Close(rulesetFd)

	for _, p := range cfg.ROPaths {
		if err := addPathRule(rulesetFd, p, readOnlyAccess&handledFS); err != nil {
			ushlog.Debug("security: landlock RO rule failed", "path", p, "err", err)
		}
	}

	// RW rules union with the RO baseline for these paths.
	for _, p := range cfg.RWPaths {
		if err := addPathRule(rulesetFd, p, fullAccess&handledFS); err != nil {
			ushlog.Debug("security: landlock RW rule failed", "path", p, "err", err)
		}
	}

	// Enforce no-new-privs (required before restrict_self; also required for
	// seccomp without CAP_SYS_ADMIN in the init user namespace).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("security: PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// Apply the ruleset to the calling thread/process.
	if err := landlockRestrictSelf(rulesetFd); err != nil {
		return fmt.Errorf("security: landlock_restrict_self: %w", err)
	}

	ushlog.Info("security: Landlock active",
		"abi", abiVersion,
		"ro_paths", len(cfg.ROPaths),
		"rw_paths", len(cfg.RWPaths))
	return nil
}

// GuestLandlockConfig builds the Landlock policy for a ush guest session.
//
// Policy: allow read+exec everywhere (under /), then grant write access
// to mutable paths (home, runtime, tmp, run, var, etc.). This prevents
// any process inside the guest from writing to /usr, /bin, /sbin, /lib, /lib64,
// which are read-only bind mounts from the host.
//
// homeDir is the user's home directory, xdgRuntime is XDG_RUNTIME_DIR,
// storageDir is the ush storage path.
func GuestLandlockConfig(homeDir, xdgRuntime, storageDir string) LandlockConfig {
	// "/" as RO grants read+exec everywhere, establishing the baseline.
	// All subdirectory rules are additive (union), so RW paths below will
	// get write access in addition to the baseline read+exec.
	roPaths := []string{"/"}

	// Paths the guest processes are allowed to write freely.
	rwPaths := []string{"/tmp", "/run", "/var", "/etc", "/dev"}
	if homeDir != "" {
		rwPaths = append(rwPaths, homeDir)
	}
	if xdgRuntime != "" && xdgRuntime != homeDir {
		rwPaths = append(rwPaths, xdgRuntime)
	}
	if storageDir != "" {
		rwPaths = append(rwPaths, storageDir)
	}

	return LandlockConfig{ROPaths: roPaths, RWPaths: rwPaths}
}

// LandlockStatus reports whether the running kernel supports Landlock and, if
// so, the ABI version. A false result means ush's filesystem containment
// boundary is NOT enforced because the kernel was built without
// CONFIG_SECURITY_LANDLOCK (or it is missing from CONFIG_LSM). Used by
// `guard status` and WarnIfLandlockUnavailable.
func LandlockStatus() (abi int, supported bool) {
	v, err := probeABI()
	if err != nil || v < 1 {
		return 0, false
	}
	return v, true
}

// WarnIfLandlockUnavailable prints a prominent warning to w when the kernel
// lacks Landlock, so a degraded containment posture is never silent. Returns
// true if Landlock is available.
func WarnIfLandlockUnavailable(w io.Writer) bool {
	if _, ok := LandlockStatus(); ok {
		return true
	}
	fmt.Fprintln(w, "\033[1;33mUSH WARNING: Landlock is unavailable on this kernel.\033[0m")
	fmt.Fprintln(w, "  The filesystem containment boundary is NOT enforced; ush is relying")
	fmt.Fprintln(w, "  on namespaces + seccomp only. Rebuild the kernel with")
	fmt.Fprintln(w, "  CONFIG_SECURITY_LANDLOCK=y and \"landlock\" in CONFIG_LSM")
	fmt.Fprintln(w, "  (see docs/SECURITY-BUILD.md in the Sinty OS repo).")
	return false
}

// probeABI returns the Landlock ABI version supported by the kernel.
// LANDLOCK_CREATE_RULESET_VERSION (flag=1) with zero size returns the ABI version.
func probeABI() (int, error) {
	// The version query requires attr==NULL and size==0; passing a non-NULL
	// attr (even a zero-valued one) makes the kernel reject the call with
	// EINVAL, which ush misread as "Landlock unsupported" and silently dropped
	// the filesystem containment on every kernel that actually has Landlock.
	ret, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, 1)
	if errno != 0 {
		return 0, errno
	}
	return int(ret), nil
}

// abiHandledFS returns the handled_access_fs mask for a given ABI version.
func abiHandledFS(abi int) uint64 {
	switch {
	case abi >= 4:
		return landlockAccessFSV4
	case abi >= 3:
		return landlockAccessFSV3
	case abi >= 2:
		return landlockAccessFSV2
	default:
		return landlockAccessFSV1
	}
}

// landlockCreateRuleset wraps the landlock_create_ruleset syscall.
func landlockCreateRuleset(attr *RulesetAttr, size uint) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(attr)), uintptr(size), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

// addPathRule opens the path and adds a LANDLOCK_RULE_PATH_BENEATH rule.
func addPathRule(rulesetFd int, path string, access uint64) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	attr := PathBeneathAttr{
		AllowedAccess: access,
		ParentFd:      int32(fd.Fd()),
	}

	const LANDLOCK_RULE_PATH_BENEATH = 1
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFd),
		LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)))
	if errno != 0 {
		return errno
	}
	return nil
}

// landlockRestrictSelf wraps the landlock_restrict_self syscall.
func landlockRestrictSelf(rulesetFd int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
