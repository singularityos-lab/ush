// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package security

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/singularityos-lab/ush/internal/broker"
	"github.com/singularityos-lab/ush/internal/guardproto"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"golang.org/x/sys/unix"
)

// EventSink receives behavioural telemetry from the supervisor. It is the EDR
// feed the Singularity Guard daemon (singd) consumes for its behavioural
// correlator. Implementations MUST be non-blocking: a sink must never stall a
// guest syscall waiting on a slow or absent consumer.
type EventSink interface {
	EmitGuardEvent(guardproto.Event)
}

// seccompNotif mirrors struct seccomp_notif (80 bytes on amd64).
// Must match kernel ABI exactly.
type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

// seccompData mirrors struct seccomp_data (64 bytes).
type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// seccompNotifResp mirrors struct seccomp_notif_resp (24 bytes on amd64).
type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// IOCTL numbers for amd64.
// SECCOMP_IOCTL_NOTIF_RECV = _IOWR('!', 0, 80-byte struct) = 0xC0502100
// SECCOMP_IOCTL_NOTIF_SEND = _IOWR('!', 1, 24-byte struct) = 0xC0182101
const (
	ioctlNotifRecv = uintptr((3 << 30) | (80 << 16) | ('!' << 8) | 0)
	ioctlNotifSend = uintptr((3 << 30) | (24 << 16) | ('!' << 8) | 1)
	// SECCOMP_IOCTL_NOTIF_ID_VALID = _IOW('!', 2, __u64): confirms the
	// notification cookie still refers to a live, blocked syscall before we act
	// on data read from the target's memory.
	ioctlNotifIDValid = uintptr((1 << 30) | (8 << 16) | ('!' << 8) | 2)
)

// notifIDValid reports whether the seccomp notification id is still valid.
// If the target thread died or was interrupted, the id is stale and any data
// we read from its memory is untrustworthy, so callers must fail closed.
func (s *Supervisor) notifIDValid(id uint64) bool {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(s.notifFd), ioctlNotifIDValid,
		uintptr(unsafe.Pointer(&id)))
	return errno == 0
}

// SECCOMP_IOCTL_NOTIF_ADDFD = _IOW('!', 3, struct seccomp_notif_addfd) (24 bytes).
// Lets the supervisor install one of ITS OWN fds into the target process. This
// is how "builtin" networking works: the guest runs in a fully isolated net
// namespace, and for an approved connect() the supervisor (which lives in the
// host net namespace) opens the real connection and injects the connected fd
// into the guest, replacing the guest's placeholder socket. No userspace TCP/IP
// stack (no pasta) and the CONTINUE TOCTOU is gone: the supervisor connects the
// fd itself instead of letting the kernel re-read guest memory.
const ioctlNotifAddfd = uintptr((1 << 30) | (24 << 16) | ('!' << 8) | 3)

const seccompAddfdFlagSetfd = 1 // install at a specific fd number, replacing it

type seccompNotifAddfd struct {
	ID         uint64
	Flags      uint32
	Srcfd      uint32
	Newfd      uint32
	NewfdFlags uint32
}

// SetBuiltinNet enables built-in (pasta-free) networking: connect() egress is
// serviced by the supervisor via fd injection. Requires an isolated guest netns.
func (s *Supervisor) SetBuiltinNet(v bool) { s.builtinNet.Store(v) }

// injectFd installs srcfd into the target process at fd number newfd (replacing
// whatever is there), associated with the given notification id.
func (s *Supervisor) injectFd(id uint64, srcfd, newfd int) error {
	a := seccompNotifAddfd{
		ID:    id,
		Flags: seccompAddfdFlagSetfd,
		Srcfd: uint32(srcfd),
		Newfd: uint32(newfd),
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(s.notifFd), ioctlNotifAddfd, uintptr(unsafe.Pointer(&a)))
	if errno != 0 {
		return errno
	}
	return nil
}

const (
	sysPidfdOpen  = 434
	sysPidfdGetfd = 438
)

// tgidOf returns the thread-group leader pid for a thread tid, read from
// /proc/<tid>/status. Falls back to the tid itself if it cannot be read.
func tgidOf(tid uint32) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return int(tid)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:"))); err == nil {
				return v
			}
		}
	}
	return int(tid)
}

// connectViaPidfd services an approved connect() in built-in mode. The guest's
// socket (created in the host net namespace at socket() time and injected) is
// fetched into the supervisor via pidfd_getfd, connected to the destination
// here, and dropped. Because we connect the guest's own socket directly, the
// connect TOCTOU is closed, the socket's flags (e.g. non-blocking) are honoured,
// and nothing is retained (no fd leak). Real connect errors (ECONNREFUSED,
// ENETUNREACH, EINPROGRESS for non-blocking) are propagated to the guest.
func (s *Supervisor) connectViaPidfd(n *seccompNotif, family uint16, ip net.IP, port uint16) seccompNotifResp {
	deny := seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)}

	// pidfd_open needs the thread-group leader (tgid), not a thread tid (which is
	// what the notification carries when a worker thread makes the syscall, e.g.
	// curl's resolver). Threads share the fd table, so the tgid's pidfd reaches
	// the same fd.
	pidfd, _, errno := unix.Syscall(sysPidfdOpen, uintptr(tgidOf(n.PID)), 0, 0)
	if errno != 0 {
		ushlog.Warn("security: builtin-net pidfd_open failed", "pid", n.PID, "errno", errno)
		return deny
	}
	defer unix.Close(int(pidfd))

	guestFd := int(int32(n.Data.Args[0]))
	hostFd, _, errno := unix.Syscall(sysPidfdGetfd, pidfd, uintptr(guestFd), 0)
	if errno != 0 {
		ushlog.Warn("security: builtin-net pidfd_getfd failed", "pid", n.PID, "guestfd", guestFd, "errno", errno)
		return deny
	}
	defer unix.Close(int(hostFd))

	var sa unix.Sockaddr
	if family == unix.AF_INET6 {
		var a [16]byte
		copy(a[:], ip.To16())
		sa = &unix.SockaddrInet6{Port: int(port), Addr: a}
	} else {
		var a [4]byte
		copy(a[:], ip.To4())
		sa = &unix.SockaddrInet4{Port: int(port), Addr: a}
	}
	if err := unix.Connect(int(hostFd), sa); err != nil {
		if e, ok := err.(syscall.Errno); ok && e != 0 {
			return seccompNotifResp{ID: n.ID, Error: int32(e)}
		}
		return deny
	}
	ushlog.Debug("security: builtin-net connect serviced", "pid", n.PID, "dst", ip.String(), "port", port)
	return seccompNotifResp{ID: n.ID, Val: 0}
}

// Supervisor handles seccomp-notify events from the guest.
//
// The exec whitelist is an AUDIT-GRADE layer, not a hard boundary. It uses
// inode-based validation (dev+ino), but the decision is delivered via
// SECCOMP_USER_NOTIF_FLAG_CONTINUE, which re-reads the syscall arguments from
// guest memory after we respond: a multithreaded guest can swap the path
// string in that window (the inherent seccomp-notify TOCTOU). We reduce the
// window by validating the notification is still live (NOTIF_ID_VALID) and by
// failing closed on unreadable memory, but the hard guarantees come from the
// layers below.
//
// Defense-in-depth layers:
//  1. Landlock - kernel-enforced RO filesystem policy (hard boundary)
//  2. seccomp BPF - blocks dangerous syscalls at kernel level (hard boundary)
//  3. namespace isolation - guest processes cannot see/affect host (hard boundary)
//  4. This supervisor + exec whitelist - audit-grade restriction on unknown execs
type Supervisor struct {
	notifFd       int
	whitelist     *ExecWhitelist
	brokerClient  *broker.Client
	permissive    atomic.Bool // when true: log denials but always continue
	devMode       atomic.Bool // true: dsh developer world, audit-only (sticky)
	netnsIsolated atomic.Bool // true when the guest has its OWN net namespace
	builtinNet    atomic.Bool // true: service egress via fd injection (no pasta)
	simpleMode    atomic.Bool // true: Android-style capability prompts (default)
	sink          EventSink   // optional behavioural telemetry feed (singd)

	// execStrip holds the guest-absolute path prefixes that are bound read-write
	// straight from the host. Anything the guest makes executable under one of
	// them is masked back to non-executable, so the host can never run what the
	// guest wrote there. nil/empty disables the feature.
	execStrip atomic.Pointer[[]string]

	// execExempt holds trusted developer directories (user-confirmed via the
	// broker). They are exempt from exec stripping even when they sit under an
	// execStrip prefix, so the user can build-and-run there on purpose.
	execExempt atomic.Pointer[[]string]
}

// SetExecStripPrefixes records the host-backed read-write share prefixes under
// which the guest must not be able to create executable files. Pass guest-
// absolute paths. Safe to call once before guest traffic starts.
func (s *Supervisor) SetExecStripPrefixes(prefixes []string) {
	cp := append([]string(nil), prefixes...)
	s.execStrip.Store(&cp)
}

// SetTrustedDevDirs records user-confirmed developer directories that are exempt
// from exec stripping (full host access, by explicit choice).
func (s *Supervisor) SetTrustedDevDirs(dirs []string) {
	cp := append([]string(nil), dirs...)
	s.execExempt.Store(&cp)
}

// SetSimplePermissions selects the permission UX. In simple mode (the default),
// network "just works" (the host is protected structurally) and only sensitive
// capabilities prompt, once per app. In fine mode every connect/device/mount is
// mediated and prompted individually (power-user / red-team).
func (s *Supervisor) SetSimplePermissions(v bool) { s.simpleMode.Store(v) }

// deviceCapability maps a /dev path to the human capability it represents, for
// simple-mode prompts ("X wants to use the Camera"). Empty means generic device.
func deviceCapability(path string) string {
	switch {
	case strings.HasPrefix(path, "/dev/video") || strings.HasPrefix(path, "/dev/v4l"):
		return "camera"
	case strings.HasPrefix(path, "/dev/snd") || path == "/dev/dsp" || strings.HasPrefix(path, "/dev/audio"):
		return "microphone"
	case strings.HasPrefix(path, "/dev/dri") || strings.HasPrefix(path, "/dev/nvidia"):
		return "gpu"
	case strings.HasPrefix(path, "/dev/input"):
		return "input"
	case strings.HasPrefix(path, "/dev/bus/usb") || strings.HasPrefix(path, "/dev/ttyUSB") || strings.HasPrefix(path, "/dev/ttyACM"):
		return "usb"
	default:
		return ""
	}
}

// capabilityLabel is the user-facing name of a capability.
func capabilityLabel(cap string) string {
	switch cap {
	case "camera":
		return "Camera"
	case "microphone":
		return "Microphone"
	case "gpu":
		return "GPU / graphics acceleration"
	case "input":
		return "input devices"
	case "usb":
		return "USB devices"
	default:
		return "a device"
	}
}

// SetNetnsIsolated tells the supervisor whether the guest runs in a dedicated
// network namespace (e.g. pasta active). When isolated, 127.0.0.1 is genuinely
// the guest's own loopback and is safe to exempt. When NOT isolated (shared
// host network fallback), 127.0.0.1 is the HOST's loopback: host-local services
// (sshd, adb, CUPS, ...) are reachable, so loopback must be mediated/denied.
func (s *Supervisor) SetNetnsIsolated(v bool) { s.netnsIsolated.Store(v) }

// SetEventSink attaches a behavioural telemetry sink. Pass nil to detach.
// Safe to call once during setup, before heavy traffic.
func (s *Supervisor) SetEventSink(sink EventSink) { s.sink = sink }

// emit forwards an event to the sink, if one is attached. Nil-safe and, by the
// EventSink contract, non-blocking.
func (s *Supervisor) emit(kind guardproto.EventKind, pid uint32, path, dest, detail string) {
	if s.sink == nil {
		return
	}
	s.sink.EmitGuardEvent(guardproto.Event{
		Kind:   kind,
		PID:    pid,
		Comm:   procName(pid),
		Path:   path,
		Dest:   dest,
		Detail: detail,
	})
}

// NewSupervisor creates a Supervisor.
// If whitelist is nil, all execs are allowed (audit mode).
// Start in permissive mode; call SetPermissive(false) to enforce.
func NewSupervisor(notifFd int, whitelist *ExecWhitelist) *Supervisor {
	s := &Supervisor{
		notifFd:   notifFd,
		whitelist: whitelist,
	}
	s.permissive.Store(true) // safe default during startup
	return s
}

// SetBrokerClient attaches a host-side broker client to the supervisor.
// When set, sensitive syscalls trigger a permission dialog instead of
// just being logged. Automatically switches out of permissive mode.
func (s *Supervisor) SetBrokerClient(c *broker.Client) {
	s.brokerClient = c
	if !s.devMode.Load() {
		s.permissive.Store(false) // broker present: enforce
	}
}

// SetDevMode marks the supervisor as serving the developer (dsh) world. It keeps
// the supervisor audit-only even once the broker is attached.
func (s *Supervisor) SetDevMode(v bool) {
	s.devMode.Store(v)
	if v {
		s.permissive.Store(true)
	}
}

// SetPermissive controls enforcement mode.
// true = log but allow (audit mode, safe during pkg install / startup).
// false = enforce whitelist (block unapproved execs).
func (s *Supervisor) SetPermissive(v bool) {
	s.permissive.Store(v)
}

// Run starts the supervisor loop. Blocks until notifFd is closed.
// Call in a goroutine. Each incoming notification is dispatched to its own
// goroutine so that a slow broker dialog for one syscall never blocks other
// concurrent syscalls (e.g. every connect() apt makes would stall otherwise).
func (s *Supervisor) Run() {
	ushlog.Info("security: seccomp supervisor started")
	defer ushlog.Info("security: seccomp supervisor stopped")

	for {
		var notif seccompNotif
		_, _, errno := unix.Syscall(unix.SYS_IOCTL,
			uintptr(s.notifFd), ioctlNotifRecv,
			uintptr(unsafe.Pointer(&notif)))
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return // fd closed or fatal error
		}

		// copy it, else every goroutine races on the same loop var
		n := notif
		go func() {
			resp, responded := s.handleNotif(&n)
			// Built-in socket() injection responds via ADDFD_SEND itself; in
			// that case we must NOT send a second response.
			if responded {
				return
			}
			unix.Syscall(unix.SYS_IOCTL,
				uintptr(s.notifFd), ioctlNotifSend,
				uintptr(unsafe.Pointer(&resp)))
		}()
	}
}

// Stop closes the notification fd, causing Run to return.
func (s *Supervisor) Stop() { unix.Close(s.notifFd) }

// handleNotif dispatches a notification. The bool is true when the handler has
// already responded to the notification itself (ADDFD_SEND path).
func (s *Supervisor) handleNotif(n *seccompNotif) (seccompNotifResp, bool) {
	const (
		sysExecve    = 59
		sysExecveat  = 322
		sysSocket    = 41
		sysConnect   = 42
		sysOpenat    = 257
		sysMount     = 165
		sysChmod     = 90
		sysFchmod    = 91
		sysFchmodat  = 268
		sysFchmodat2 = 452
	)
	switch n.Data.Nr {
	case sysExecve, sysExecveat:
		return s.handleExecve(n), false
	case sysSocket:
		if r, done := s.builtinSocket(n); done {
			return r, true
		}
		return s.handleSocket(n), false
	case sysConnect:
		return s.handleConnect(n), false
	case sysOpenat:
		return s.handleOpenat(n), false
	case sysMount:
		return s.handleMount(n), false
	case sysChmod, sysFchmod, sysFchmodat, sysFchmodat2:
		return s.handleChmod(n), false
	}
	return seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}, false
}

// builtinSocket, in built-in networking mode, creates the inet TCP/UDP socket
// in the HOST net namespace and injects it into the guest, so the guest's
// "socket" is actually wired to the host network from birth (the guest netns
// has only loopback). The returned bool is true when it handled+responded.
// Non-inet / raw / non-builtin cases return false and fall through to the
// normal handleSocket policy.
func (s *Supervisor) builtinSocket(n *seccompNotif) (seccompNotifResp, bool) {
	if !s.builtinNet.Load() {
		return seccompNotifResp{}, false
	}
	domain := int(int32(n.Data.Args[0]))
	rawType := int(int32(n.Data.Args[1]))
	sockType := rawType & 0xf
	proto := int(int32(n.Data.Args[2]))
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return seccompNotifResp{}, false
	}
	if sockType != unix.SOCK_STREAM && sockType != unix.SOCK_DGRAM {
		return seccompNotifResp{}, false // raw etc. -> normal gating
	}

	denied := func() (seccompNotifResp, bool) {
		// Respond with EPERM via a normal response (not SEND).
		unix.Syscall(unix.SYS_IOCTL, uintptr(s.notifFd), ioctlNotifSend,
			uintptr(unsafe.Pointer(&seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)})))
		return seccompNotifResp{}, true
	}

	hostFd, err := unix.Socket(domain, rawType, proto)
	if err != nil {
		return denied()
	}
	// Inject a dup into the guest and drop our own copy: connect() later reaches
	// the guest's fd via pidfd_getfd, so nothing needs to be retained (no leak).
	_, err = s.injectFdSend(n.ID, hostFd)
	unix.Close(hostFd)
	if err != nil {
		return denied()
	}
	return seccompNotifResp{}, true
}

// injectFdSend installs srcfd into the target and atomically responds to the
// notification, returning the new fd number as the intercepted syscall result.
func (s *Supervisor) injectFdSend(id uint64, srcfd int) (int, error) {
	const seccompAddfdFlagSend = 2
	a := seccompNotifAddfd{ID: id, Flags: seccompAddfdFlagSend, Srcfd: uint32(srcfd)}
	r, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(s.notifFd), ioctlNotifAddfd, uintptr(unsafe.Pointer(&a)))
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// handleExecve audits/enforces the exec whitelist.
// All path resolution uses /proc/<pid>/root/ so the host-side hash matches
// the file the child would actually execute.
func (s *Supervisor) handleExecve(n *seccompNotif) seccompNotifResp {
	allowResp := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	denyResp := seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)}

	// Fail closed when enforcing the whitelist: if we cannot read the path we
	// cannot validate it, and an attacker can deliberately make the read fail
	// (e.g. argv[0] straddling an unmapped page) to slip past the check.
	enforcing := s.whitelist != nil && !s.permissive.Load()

	guestPath, err := readStringFromProcess(int(n.PID), uintptr(n.Data.Args[0]))
	if err != nil {
		ushlog.Debug("security: execve: cannot read path from child mem",
			"pid", n.PID, "err", err)
		if enforcing {
			ushlog.Warn("security: exec denied (unreadable path, failing closed)", "pid", n.PID)
			return denyResp
		}
		return allowResp
	}

	// /proc/<pid>/root/<guestPath> resolves through the child's mount namespace.
	hostPath := filepath.Join(fmt.Sprintf("/proc/%d/root", n.PID), guestPath)

	// Behavioural telemetry: every exec is interesting to the correlator.
	s.emit(guardproto.EventExec, n.PID, guestPath, "", "")

	if s.whitelist == nil {
		ushlog.Debug("security: exec (no whitelist)", "path", guestPath)
		return allowResp
	}

	allowed := s.whitelist.Allow(hostPath, guestPath)
	if !allowed {
		if s.permissive.Load() {
			ushlog.Debug("security: exec audit-deny (permissive, allowed)",
				"path", guestPath, "pid", n.PID)
			return allowResp
		}
		ushlog.Warn("security: exec blocked (not in whitelist)",
			"path", guestPath, "pid", n.PID)
		return denyResp
	}

	// Re-validate the notification before continuing. If it went stale between
	// the read and now, the validated path may no longer be what the kernel
	// will execute; fail closed when enforcing.
	if enforcing && !s.notifIDValid(n.ID) {
		ushlog.Warn("security: exec denied (notification went stale)", "path", guestPath, "pid", n.PID)
		return denyResp
	}

	ushlog.Debug("security: exec allowed", "path", guestPath, "pid", n.PID)
	return allowResp
}
