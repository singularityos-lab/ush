// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package security

import (
	"fmt"
	"unsafe"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"golang.org/x/sys/unix"
)

// BPF instruction opcodes (used to build seccomp BPF programs).
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x15
	bpfJGE = 0x35
	bpfK   = 0x00
	bpfRET = 0x06

	syscallNROffset = 0 // offsetof(struct seccomp_data, nr)
	archOffset      = 4 // offsetof(struct seccomp_data, arch)

	// AUDIT_ARCH_X86_64: the expected runtime architecture.
	auditArchX86_64 = 0xC000003E

	// __X32_SYSCALL_BIT: x32 ABI syscalls share AUDIT_ARCH_X86_64 but set this
	// high bit in the syscall number. A bare nr comparison never matches them,
	// so they would fall through to ALLOW (a well-known seccomp bypass, e.g.
	// x32 execve/ptrace/setns). Any nr with this bit set is rejected.
	x32SyscallBit = 0x40000000
)

// bpfStmt builds a BPF statement (no jump).
func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

// bpfJump builds a BPF conditional jump instruction.
func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// InstallSeccompFilter installs a seccomp BPF filter using SECCOMP_FILTER_FLAG_TSYNC
// so it applies to ALL threads of the calling process. Dangerous syscalls are
// blocked with EPERM; all others are allowed.
//
// We do NOT block mount/umount2 because the pkg install flow mounts overlays
// inside the guest's own mount namespace. Those mounts never affect the host.
// The user + mount namespace isolation already prevents host escape.
//
// We DO block: ptrace, kexec_*, bpf, setns, perf_event_open, and the new
// Linux mount API (open_tree, move_mount, fsopen, fsconfig, fsmount, fspick,
// mount_setattr) - these are either host-escape vectors or attack surface.
//
// Must be called after PR_SET_NO_NEW_PRIVS (which ApplyLandlock already sets).
func InstallSeccompFilter() error {
	// All syscall numbers are for amd64. The BPF program validates the
	// architecture at runtime and kills the process if it doesn't match
	// (prevents arch-confusion attacks).
	const (
		sysPtrace        = 101
		sysKexecLoad     = 246
		sysKexecFileLd   = 320
		sysBpf           = 321
		sysSetns         = 308
		sysPerfEventOpen = 241
		// New Linux mount API (kernel 5.2+) - more surface, block for hardening.
		sysOpenTree     = 428
		sysMoveMount    = 429
		sysFsopen       = 430
		sysFsconfig     = 431
		sysFsmount      = 432
		sysFspick       = 433
		sysMountSetattr = 442
	)

	blocked := []uint32{
		sysPtrace, sysKexecLoad, sysKexecFileLd,
		sysBpf, sysSetns, sysPerfEventOpen,
		sysOpenTree, sysMoveMount, sysFsopen,
		sysFsconfig, sysFsmount, sysFspick, sysMountSetattr,
	}

	filter := buildBlockFilter(blocked)
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// SECCOMP_FILTER_FLAG_TSYNC = 1: sync filter to all existing threads.
	// This can return EAGAIN if a thread state changes; retry once.
	const flagTsync = 1
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		flagTsync,
		uintptr(unsafe.Pointer(prog)))
	if errno == unix.EAGAIN {
		// Retry once - thread state may have settled.
		_, _, errno = unix.Syscall(unix.SYS_SECCOMP,
			unix.SECCOMP_SET_MODE_FILTER,
			flagTsync,
			uintptr(unsafe.Pointer(prog)))
	}
	if errno != 0 {
		return fmt.Errorf("security: seccomp filter (tsync): %w", errno)
	}

	ushlog.Info("security: seccomp block filter installed (all threads)",
		"blocked_syscalls", len(blocked))
	return nil
}

// buildBlockFilter constructs a BPF program that blocks the given syscall
// numbers with EPERM and allows everything else.
func buildBlockFilter(blocked []uint32) []unix.SockFilter {
	var insns []unix.SockFilter

	// Load and validate architecture.
	insns = append(insns,
		bpfStmt(bpfLD|bpfW|bpfABS, archOffset),
		bpfJump(bpfJMP|bpfJEQ|bpfK, auditArchX86_64, 1, 0),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_KILL),
	)

	// Load syscall number.
	insns = append(insns, bpfStmt(bpfLD|bpfW|bpfABS, syscallNROffset))

	// Reject any x32 ABI syscall (high bit set) before the nr comparisons,
	// otherwise the blocks below (ptrace, bpf, setns, ...) are trivially
	// bypassed via the x32 calling convention.
	insns = append(insns,
		bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ERRNO|(uint32(unix.EPERM)&unix.SECCOMP_RET_DATA)),
	)

	// For each blocked syscall: if nr == syscall, return ERRNO(EPERM).
	// Fall-through after all checks is ALLOW.
	for _, nr := range blocked {
		insns = append(insns,
			bpfJump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1),
			bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ERRNO|(uint32(unix.EPERM)&unix.SECCOMP_RET_DATA)),
		)
	}

	// Default: allow.
	insns = append(insns, bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ALLOW))
	return insns
}

// InstallSeccompNotifyFilter installs a seccomp filter that uses
// SECCOMP_RET_USER_NOTIF for execve/execveat syscalls, and blocks dangerous
// syscalls directly. Returns the notification file descriptor.
//
// NOTE: NEW_LISTENER and TSYNC are mutually exclusive (EINVAL if combined).
// This filter only covers the calling thread; all exec'd children inherit it
// automatically. Install the TSYNC blocking filter first via InstallSeccompFilter.
//
// NOTE: seccomp-notify CONTINUE has an inherent TOCTOU race. The exec whitelist
// here is best-effort / audit-grade, not a hard security boundary. Landlock +
// the blocking filter provide the hard guarantees.
func InstallSeccompNotifyFilter() (notifFd int, err error) {
	return installSeccompNotifyFilter(false)
}

// InstallSeccompNotifyFilterDev installs the developer (dsh) notify filter. It
// still notifies the broker/supervisor on the same syscalls, but it does NOT
// hard-block the namespace/mount-API/bpf syscalls that rootless container
// runtimes (podman, crun) require: setns, open_tree/move_mount/fsopen/...,
// mount_setattr, bpf. The genuinely catastrophic ones (ptrace, kexec) stay
// blocked. dsh is a developer environment, not a security boundary against the
// code you run in it.
func InstallSeccompNotifyFilterDev() (notifFd int, err error) {
	return installSeccompNotifyFilter(true)
}

func installSeccompNotifyFilter(relaxed bool) (notifFd int, err error) {
	const (
		sysExecve      = 59
		sysExecveat    = 322
		sysPtrace      = 101
		sysKexecLoad   = 246
		sysKexecFileLd = 320
		sysBpf         = 321
		sysSetns       = 308
		// New mount API.
		sysOpenTree     = 428
		sysMoveMount    = 429
		sysFsopen       = 430
		sysFsconfig     = 431
		sysFsmount      = 432
		sysFspick       = 433
		sysMountSetattr = 442
	)

	directBlock := []uint32{
		sysPtrace, sysKexecLoad, sysKexecFileLd, sysBpf, sysSetns,
		sysOpenTree, sysMoveMount, sysFsopen, sysFsconfig, sysFsmount,
		sysFspick, sysMountSetattr,
	}
	if relaxed {
		// Developer profile: only the catastrophic syscalls stay blocked.
		directBlock = []uint32{sysPtrace, sysKexecLoad, sysKexecFileLd}
	}
	notifySyscalls := []uint32{
		sysExecve, sysExecveat,
		41,  // socket   (raw socket creation: ping, nmap, etc.)
		42,  // connect  (network policy)
		257, // openat   (device access under /dev/*)
		165, // mount    (filesystem mount)
		90,  // chmod    (strip +x on host-backed writes)
		91,  // fchmod   (strip +x on host-backed writes)
		268, // fchmodat (strip +x on host-backed writes)
		452, // fchmodat2 (strip +x on host-backed writes, newer kernels)
	}

	filter := buildNotifyFilter(notifySyscalls, directBlock)
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// SECCOMP_FILTER_FLAG_NEW_LISTENER returns the notification fd.
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		uintptr(unsafe.Pointer(prog)))
	if errno != 0 {
		return 0, fmt.Errorf("security: seccomp notify filter: %w", errno)
	}

	ushlog.Info("security: seccomp notify filter installed",
		"notify_syscalls", len(notifySyscalls),
		"blocked_syscalls", len(directBlock))
	return int(fd), nil
}

// buildNotifyFilter builds a BPF program that:
//   - sends SECCOMP_RET_USER_NOTIF for the notify syscalls
//   - returns SECCOMP_RET_ERRNO|EPERM for the blocked syscalls
//   - allows everything else
func buildNotifyFilter(notify, block []uint32) []unix.SockFilter {
	var insns []unix.SockFilter

	// Validate architecture.
	insns = append(insns,
		bpfStmt(bpfLD|bpfW|bpfABS, archOffset),
		bpfJump(bpfJMP|bpfJEQ|bpfK, auditArchX86_64, 1, 0),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_KILL),
	)

	// Load syscall number.
	insns = append(insns, bpfStmt(bpfLD|bpfW|bpfABS, syscallNROffset))

	// Reject any x32 ABI syscall (high bit set) before the nr comparisons:
	// without this, x32 execve/connect/etc. skip both the notify and block
	// arms and fall through to ALLOW.
	insns = append(insns,
		bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ERRNO|(uint32(unix.EPERM)&unix.SECCOMP_RET_DATA)),
	)

	// Notify syscalls.
	for _, nr := range notify {
		insns = append(insns,
			bpfJump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1),
			bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_USER_NOTIF),
		)
	}

	// Directly blocked syscalls.
	for _, nr := range block {
		insns = append(insns,
			bpfJump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1),
			bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ERRNO|(uint32(unix.EPERM)&unix.SECCOMP_RET_DATA)),
		)
	}

	// Default: allow.
	insns = append(insns, bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ALLOW))
	return insns
}

// InstallJailSeccomp installs a per-app jail seccomp filter on the calling
// thread and all threads (TSYNC). It always blocks the baseline dangerous
// syscalls; when allowNet is false it additionally denies creation of
// AF_INET/AF_INET6 sockets, so the jailed app has no network (AF_UNIX and
// other local IPC still work). Must be called after PR_SET_NO_NEW_PRIVS.
func InstallJailSeccomp(allowNet bool) error {
	filter := buildJailFilter(allowNet)
	prog := &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	const flagTsync = 1
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER, flagTsync, uintptr(unsafe.Pointer(prog)))
	if errno != 0 {
		return fmt.Errorf("security: jail seccomp: %w", errno)
	}
	return nil
}

// buildJailFilter builds the per-app jail BPF program. Baseline dangerous
// syscalls are denied with EPERM; when allowNet is false, socket(AF_INET) and
// socket(AF_INET6) are denied too (the domain is the first argument, examined
// inline). Everything else is allowed.
func buildJailFilter(allowNet bool) []unix.SockFilter {
	const (
		sysSocket        = 41
		sysPtrace        = 101
		sysKexecLoad     = 246
		sysKexecFileLd   = 320
		sysBpf           = 321
		sysSetns         = 308
		sysPerfEventOpen = 241
		sysOpenTree      = 428
		sysMoveMount     = 429
		sysFsopen        = 430
		sysFsconfig      = 431
		sysFsmount       = 432
		sysFspick        = 433
		sysMountSetattr  = 442
		afInet           = 2
		afInet6          = 10
		argOffset0       = 16 // offsetof(struct seccomp_data, args[0]) low word
	)
	blocked := []uint32{
		sysPtrace, sysKexecLoad, sysKexecFileLd, sysBpf, sysSetns,
		sysPerfEventOpen, sysOpenTree, sysMoveMount, sysFsopen, sysFsconfig,
		sysFsmount, sysFspick, sysMountSetattr,
	}
	eperm := bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ERRNO|(uint32(unix.EPERM)&unix.SECCOMP_RET_DATA))
	allow := bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_ALLOW)

	var insns []unix.SockFilter
	// Validate architecture, then load the syscall number.
	insns = append(insns,
		bpfStmt(bpfLD|bpfW|bpfABS, archOffset),
		bpfJump(bpfJMP|bpfJEQ|bpfK, auditArchX86_64, 1, 0),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_KILL),
		bpfStmt(bpfLD|bpfW|bpfABS, syscallNROffset),
	)
	// Reject x32 ABI syscalls (high bit set) so the blocks below are not bypassed.
	insns = append(insns,
		bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
		eperm,
	)
	// Network denial: deny socket(AF_INET/AF_INET6). The accumulator holds nr; on
	// a non-socket nr the 5-instruction block is skipped (jf=5) leaving nr intact.
	if !allowNet {
		insns = append(insns,
			bpfJump(bpfJMP|bpfJEQ|bpfK, sysSocket, 0, 5),
			bpfStmt(bpfLD|bpfW|bpfABS, argOffset0), // A = domain
			bpfJump(bpfJMP|bpfJEQ|bpfK, afInet, 2, 0),
			bpfJump(bpfJMP|bpfJEQ|bpfK, afInet6, 1, 0),
			allow, // socket of another domain (AF_UNIX, ...) is fine
			eperm, // AF_INET/AF_INET6 denied
		)
	}
	// Baseline blocked syscalls (accumulator still holds nr).
	for _, nr := range blocked {
		insns = append(insns,
			bpfJump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1),
			eperm,
		)
	}
	insns = append(insns, allow)
	return insns
}
