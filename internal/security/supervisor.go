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

// handleSocket intercepts socket() calls and enforces policy for raw sockets.
// Regular TCP/UDP sockets are allowed here; connect() will handle their destinations.
// Raw sockets (SOCK_RAW) can bypass connect() entirely (e.g. ping, nmap) so we
// gate them here - they require explicit broker approval.
func (s *Supervisor) handleSocket(n *seccompNotif) seccompNotifResp {
	allow := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	deny := seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)}

	domain := int(n.Data.Args[0])
	sockType := int(n.Data.Args[1]) & 0xf // strip SOCK_NONBLOCK / SOCK_CLOEXEC flags

	const (
		sockRaw  = 3
		afInet   = 2
		afInet6  = 10
		afPacket = 17 // AF_PACKET (raw Ethernet, e.g. tcpdump)
		afAlg    = 38 // AF_ALG (kernel crypto API, CVE-2026-31431 vector)
	)

	// AF_ALG (kernel crypto API) is never needed in the guest and is the
	// primary vector for CVE-2026-31431 (page cache corruption via splice).
	// block it, no exceptions
	if domain == afAlg {
		ushlog.Warn("security: AF_ALG socket denied (CVE-2026-31431 vector)",
			"pid", n.PID, "type", sockType)
		return deny
	}

	// Only enforce for raw/packet sockets on inet families.
	needsApproval := sockType == sockRaw &&
		(domain == afInet || domain == afInet6 || domain == afPacket)
	if !needsApproval {
		return allow
	}

	proto := int(n.Data.Args[2])
	cmd := procName(n.PID)
	if s.permissive.Load() {
		ushlog.Debug("security: raw socket (audit)", "pid", n.PID, "cmd", cmd,
			"domain", domain, "type", sockType, "proto", proto)
		return allow
	}

	if s.brokerClient == nil {
		return allow
	}

	if s.isAppTrusted(n.PID) {
		ushlog.Debug("security: raw socket allowed (app trusted)", "pid", n.PID)
		return allow
	}

	reason := fmt.Sprintf("%s wants a raw socket (domain=%d proto=%d)", cmd, domain, proto)
	if s.brokerClient.IsAllowed("network", "raw-socket", reason) {
		ushlog.Debug("security: raw socket allowed by broker", "pid", n.PID)
		return allow
	}

	ushlog.Warn("security: raw socket denied by broker", "pid", n.PID,
		"domain", domain, "proto", proto)
	return deny
}

// handleConnect intercepts connect() syscalls and enforces network policy.
// Loopback addresses (127.x.x.x, ::1) and Unix/Netlink sockets pass freely.
// External IPv4/IPv6 connections require broker approval.
// If the supervisor is in permissive mode, all connections are logged and allowed.
func (s *Supervisor) handleConnect(n *seccompNotif) seccompNotifResp {
	allow := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	deny := seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)}

	// Fail closed when enforcing: an attacker can mask the real destination by
	// making the sockaddr unreadable or out of range, then swapping it on the
	// CONTINUE re-read. Only allow the unparseable case in permissive/audit mode.
	enforcing := s.brokerClient != nil && !s.permissive.Load()

	addrPtr := uintptr(n.Data.Args[1])
	addrLen := int(n.Data.Args[2])
	if addrLen < 2 || addrLen > 128 {
		if enforcing {
			return deny
		}
		return allow
	}

	buf, err := readBytesFromProcess(int(n.PID), addrPtr, addrLen)
	if err != nil {
		if enforcing {
			ushlog.Warn("security: connect denied (unreadable sockaddr, failing closed)", "pid", n.PID)
			return deny
		}
		return allow
	}

	family := binary.LittleEndian.Uint16(buf[0:2])

	var ip net.IP
	var port uint16

	switch family {
	case unix.AF_INET:
		if len(buf) < 8 {
			return allow
		}
		port = binary.BigEndian.Uint16(buf[2:4])
		ip = net.IP(buf[4:8])
	case unix.AF_INET6:
		if len(buf) < 24 {
			return allow
		}
		port = binary.BigEndian.Uint16(buf[2:4])
		ip = net.IP(buf[8:24])
	default:
		// AF_UNIX, AF_NETLINK, etc. - always allow.
		return allow
	}

	// Loopback handling is netns-aware. With a dedicated guest netns (pasta),
	// 127.0.0.1 is the guest's OWN loopback, safe to exempt. In the shared
	// fallback it is the HOST's loopback: hard-deny known host control surfaces
	// (ssh, adb, CUPS, Discord RPC, ...) and route the rest through the broker
	// like any external address. Link-local is never exempted either.
	if ip.IsLoopback() {
		// Exempt loopback ONLY with a real isolated guest netns whose sockets
		// stay in the guest (pasta). In built-in mode the guest's sockets are
		// host-netns sockets, so 127.0.0.1 reaches the HOST loopback; treat it
		// like the shared fallback: hard-deny host control surfaces, mediate the
		// rest.
		if s.netnsIsolated.Load() && !s.builtinNet.Load() {
			return allow
		}
		if isSensitiveHostPort(int(port)) {
			ushlog.Warn("security: blocked guest->host loopback service",
				"port", port, "pid", n.PID)
			return deny
		}
		// fall through: mediate this host-loopback connect via the broker.
	}

	resource := fmt.Sprintf("%s:%d", ip.String(), port)
	permissionResource := "tcp://" + resource

	// Behavioural telemetry: outbound connection to a non-local address.
	s.emit(guardproto.EventConnect, n.PID, "", resource, "")

	// Simple (Android-style) mode: the network capability "just works". The host
	// is protected structurally (isolated netns, sensitive host ports already
	// hard-denied above), so external egress does not prompt per-IP. Fine mode
	// falls through to per-destination broker mediation below.
	if s.simpleMode.Load() {
		return s.allowConnect(n, family, ip, port)
	}

	if s.permissive.Load() {
		ushlog.Debug("security: connect (audit)", "pid", n.PID, "dst", resource)
		return s.allowConnect(n, family, ip, port)
	}

	// No broker: fail open (can't ask user).
	if s.brokerClient == nil {
		return s.allowConnect(n, family, ip, port)
	}

	cmd := procName(n.PID)

	if s.isAppTrusted(n.PID) {
		ushlog.Debug("security: connect allowed (app trusted)", "pid", n.PID, "cmd", cmd)
		return s.allowConnect(n, family, ip, port)
	}

	reason := fmt.Sprintf("%s -> connect to %s", cmd, resource)
	if s.brokerClient.IsAllowed("network", permissionResource, reason) {
		ushlog.Debug("security: connect allowed by broker", "dst", resource)
		return s.allowConnect(n, family, ip, port)
	}

	ushlog.Warn("security: connect denied by broker", "dst", resource, "pid", n.PID)
	return deny
}

// allowConnect turns an approved external connect into either a CONTINUE (the
// guest's own socket reaches the network, e.g. with pasta or shared netns) or,
// in built-in networking mode, a supervisor-serviced connection injected back
// into the guest. Loopback stays a CONTINUE (it is the guest's own loopback in
// an isolated netns).
func (s *Supervisor) allowConnect(n *seccompNotif, family uint16, ip net.IP, port uint16) seccompNotifResp {
	// In built-in mode every approved connect (loopback included, since the
	// guest's sockets live in the host netns) is serviced by the supervisor.
	if s.builtinNet.Load() {
		return s.connectViaPidfd(n, family, ip, port)
	}
	return seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
}

// handleOpenat intercepts openat() calls to sensitive device paths.
// Runtime scratch paths under /dev are not device access.
// FS writes to /etc, /usr etc. are already blocked by Landlock.
func (s *Supervisor) handleOpenat(n *seccompNotif) seccompNotifResp {
	allow := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	deny := seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)}

	// arg1 = pathname pointer (arg0 = dirfd)
	pathPtr := uintptr(n.Data.Args[1])
	flags := int(n.Data.Args[2])

	path, err := readStringFromProcess(int(n.PID), pathPtr)
	if err != nil {
		return allow // fail open
	}

	// Only care about /dev/* access.
	if !strings.HasPrefix(path, "/dev/") {
		return allow
	}

	if isSafeDevPath(path) {
		return allow
	}

	// Read-only access to safe pseudo-devices is always fine.
	safeDevices := []string{"/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full"}
	for _, safe := range safeDevices {
		if path == safe {
			return allow
		}
	}

	// Write access to any device, or read access to a non-safe device.
	writeAccess := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0
	accessType := "read"
	if writeAccess {
		accessType = "write"
	}

	// Behavioural telemetry: access to a sensitive /dev path.
	s.emit(guardproto.EventOpen, n.PID, path, "", accessType)

	if s.permissive.Load() {
		ushlog.Debug("security: device access (audit)", "path", path, "access", accessType, "pid", n.PID)
		return allow
	}

	if s.brokerClient == nil {
		return allow
	}

	if s.isAppTrusted(n.PID) {
		ushlog.Debug("security: device access allowed (app trusted)", "path", path, "pid", n.PID)
		return allow
	}

	// Simple (Android-style) mode: decide per (app, capability), once, with a
	// human prompt ("X wants to use the Camera"), instead of per device path.
	if s.simpleMode.Load() {
		exe := procExe(n.PID)
		if exe == "" {
			exe = procName(n.PID)
		}
		capability := deviceCapability(path)
		if capability == "" {
			// Unknown device: fall back to a per-path prompt.
			reason := fmt.Sprintf("%s wants %s access to %s", procName(n.PID), accessType, path)
			if s.brokerClient.IsAllowed("device", path, reason) {
				return allow
			}
			ushlog.Warn("security: device access denied", "path", path, "pid", n.PID)
			return deny
		}
		reason := fmt.Sprintf("%s wants to use the %s", procName(n.PID), capabilityLabel(capability))
		if s.brokerClient.IsAllowed("cap."+capability, exe, reason) {
			ushlog.Debug("security: capability allowed", "cap", capability, "exe", exe)
			return allow
		}
		ushlog.Warn("security: capability denied", "cap", capability, "exe", exe, "pid", n.PID)
		return deny
	}

	reason := fmt.Sprintf("%s wants %s access to %s", procName(n.PID), accessType, path)
	if s.brokerClient.IsAllowed("device", path, reason) {
		ushlog.Debug("security: device access allowed", "path", path)
		return allow
	}

	ushlog.Warn("security: device access denied", "path", path, "pid", n.PID)
	return deny
}

// isSensitiveHostPort reports whether a loopback port is a known host control
// surface that the guest must never reach when the network is shared. These are
// the ports a sandboxed process could use to pivot into the host or its devices
// (e.g. adb, Discord RPC, CUPS, sshd).
func isSensitiveHostPort(port int) bool {
	switch {
	case port == 22: // ssh
		return true
	case port == 23: // telnet
		return true
	case port == 25: // smtp
		return true
	case port == 111: // rpcbind
		return true
	case port == 631: // CUPS
		return true
	case port == 5037: // adb server (device control)
		return true
	case port == 5353: // mDNS
		return true
	case port >= 6000 && port <= 6063: // X11
		return true
	case port >= 6463 && port <= 6472: // Discord RPC
		return true
	case port == 6566: // Discord RPC (alt)
		return true
	case port == 2375 || port == 2376: // docker daemon
		return true
	case port == 5432 || port == 3306 || port == 6379 || port == 27017: // postgres/mysql/redis/mongo
		return true
	default:
		return false
	}
}

func isSafeDevPath(path string) bool {
	safePrefixes := []string{
		"/dev/shm/",
		"/dev/fd/",
		"/dev/pts/",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	switch path {
	case "/dev/shm", "/dev/fd", "/dev/pts", "/dev/stdin", "/dev/stdout", "/dev/stderr":
		return true
	default:
		return false
	}
}

// handleMount intercepts mount() calls. Within the guest mount namespace,
// mount can't affect the host, but we still ask for approval so the user
// is aware of filesystem changes inside the runtime.
// Mount enforcement is opt-in via USH_SECCOMP_ENFORCE_MOUNT=1 because
// pkg install uses bind mounts internally.
func (s *Supervisor) handleMount(n *seccompNotif) seccompNotifResp {
	allow := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	deny := seccompNotifResp{ID: n.ID, Error: int32(syscall.EPERM)}

	// arg1 = target path pointer
	targetPtr := uintptr(n.Data.Args[1])
	target, err := readStringFromProcess(int(n.PID), targetPtr)
	if err != nil {
		target = "<unknown>"
	}

	// Behavioural telemetry: a mount() inside the guest.
	s.emit(guardproto.EventMount, n.PID, target, "", "")

	// Mount enforcement must be explicitly opted into (env var in guest)
	// because pkg install uses bind mounts internally.
	if os.Getenv("USH_SECCOMP_ENFORCE_MOUNT") != "1" {
		ushlog.Debug("security: mount (audit-only, set USH_SECCOMP_ENFORCE_MOUNT=1 to enforce)",
			"target", target, "pid", n.PID)
		return allow
	}

	if s.permissive.Load() {
		ushlog.Debug("security: mount (audit)", "target", target, "pid", n.PID)
		return allow
	}

	if s.brokerClient == nil {
		return allow
	}

	reason := fmt.Sprintf("%s -> mount filesystem at %s", procName(n.PID), target)
	if s.brokerClient.IsAllowed("filesystem", "mount:"+target, reason) {
		ushlog.Debug("security: mount allowed", "target", target)
		return allow
	}

	ushlog.Warn("security: mount denied", "target", target, "pid", n.PID)
	return deny
}

// atFDCWD is AT_FDCWD: a relative path is resolved against the process cwd.
const atFDCWD = -100

// handleChmod enforces the invariant "nothing the guest writes to a host-backed
// read-write share may be executable by the host". When the guest tries to add an
// executable (or set-user/group-id) bit to a file under one of those shares, the
// supervisor applies the chmod ITSELF with those bits masked off and reports
// success, so the guest's chmod "works" but the on-disk file the host sees is
// never executable. This closes the whole "guest writes what the host later runs"
// class structurally, for any tool, without a per-path denylist. Files in the
// guest's own private layers (its home, tmp, overlays) are untouched, so the
// guest can still run its own scripts.
func (s *Supervisor) handleChmod(n *seccompNotif) seccompNotifResp {
	cont := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}

	pp := s.execStrip.Load()
	if pp == nil || len(*pp) == 0 {
		return cont // feature disabled
	}

	const (
		sysChmod    = 90
		sysFchmod   = 91
		sysFchmodat = 268
	)
	var (
		mode    uint32
		absPath string
		ok      bool
	)
	switch n.Data.Nr {
	case sysChmod: // chmod(path, mode)
		mode = uint32(n.Data.Args[1])
		absPath, ok = resolveAtPath(int(n.PID), atFDCWD, uintptr(n.Data.Args[0]))
	case sysFchmod: // fchmod(fd, mode)
		mode = uint32(n.Data.Args[1])
		absPath, ok = resolveFdPath(int(n.PID), int(int32(n.Data.Args[0])))
	default: // fchmodat(dirfd, path, mode, flags) and fchmodat2(.., flags)
		mode = uint32(n.Data.Args[2])
		absPath, ok = resolveAtPath(int(n.PID), int(int32(n.Data.Args[0])), uintptr(n.Data.Args[1]))
	}
	if !ok || absPath == "" {
		return cont // cannot resolve: fail open, consistent with the other handlers
	}

	// Only act when an exec/setuid/setgid bit is requested on a host-backed share.
	if mode&0o7111 == 0 {
		return cont
	}
	if !pathHasPrefix(absPath, *pp) {
		return cont
	}
	// User-trusted developer directories keep full host access on purpose.
	if ex := s.execExempt.Load(); ex != nil && pathHasPrefix(absPath, *ex) {
		return cont
	}

	// Apply the chmod with the dangerous bits cleared, via the guest's own root so
	// we stay inside its filesystem view, then report success without running the
	// original syscall.
	masked := os.FileMode(mode &^ 0o7111 & 0o777)
	target := fmt.Sprintf("/proc/%d/root%s", n.PID, absPath)
	if err := os.Chmod(target, masked); err != nil {
		// Surface the real failure (ENOENT, EPERM, ...) to the guest instead of a
		// blanket code, so a chmod on a missing path fails exactly as it would
		// have unmediated. Never fall through to letting +x through.
		errno := errnoFromErr(err)
		if errno == 0 {
			errno = syscall.EPERM
		}
		ushlog.Debug("security: exec-strip chmod failed", "path", absPath, "errno", errno)
		return seccompNotifResp{ID: n.ID, Error: int32(errno)}
	}
	s.emit(guardproto.EventOpen, n.PID, absPath, "", "exec-bit-stripped")
	ushlog.Debug("security: stripped exec bits on host-backed write",
		"path", absPath, "mode", fmt.Sprintf("%#o->%#o", mode, uint32(masked)))
	return seccompNotifResp{ID: n.ID, Error: 0} // success; syscall not executed
}

// resolveAtPath turns a (dirfd, pathptr) pair from the guest into a guest-
// absolute path, mirroring how the kernel would resolve it.
func resolveAtPath(pid, dirfd int, ptr uintptr) (string, bool) {
	p, err := readStringFromProcess(pid, ptr)
	if err != nil || p == "" {
		return "", false
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), true
	}
	var base string
	if dirfd == atFDCWD {
		base, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	} else {
		base, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	}
	if err != nil || base == "" {
		return "", false
	}
	return filepath.Clean(filepath.Join(base, p)), true
}

// errnoFromErr extracts the underlying syscall errno from a filesystem error
// (os.Chmod returns a *PathError wrapping a syscall.Errno). Returns 0 if none.
func errnoFromErr(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return 0
}

// resolveFdPath resolves an open fd to its guest-absolute path.
func resolveFdPath(pid, fd int) (string, bool) {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil || !filepath.IsAbs(p) {
		return "", false
	}
	return p, true
}

// normHome collapses the ostree /var/home alias onto /home so prefix matching is
// robust to which spelling each side used. On ostree-based hosts /home is a
// symlink to /var/home, so the exec-strip prefixes (built from the host's home,
// possibly /var/home/...) and the path the guest actually passes (often
// /home/...) name the same files under different absolute paths. Without this the
// whole mitigation silently never matches.
func normHome(p string) string {
	if strings.HasPrefix(p, "/var/home/") {
		return "/home/" + strings.TrimPrefix(p, "/var/home/")
	}
	return p
}

// pathHasPrefix reports whether path is at or below one of the prefixes, after
// normalizing the /var/home alias on both sides.
func pathHasPrefix(path string, prefixes []string) bool {
	path = normHome(path)
	for _, pre := range prefixes {
		if pre == "" {
			continue
		}
		pre = normHome(pre)
		if path == pre || strings.HasPrefix(path, pre+"/") {
			return true
		}
	}
	return false
}

// procName returns the short command name of pid read from /proc/<pid>/comm.
// Returns "unknown" if the file cannot be read.
//
// NOTE: comm is attacker-controlled (prctl(PR_SET_NAME)), so it is used only
// for human-facing telemetry and dialog text, NEVER for a trust decision.
// Use procExe for identity.
func procName(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// procExe returns the absolute path of the executable backing pid, read from
// the kernel-maintained /proc/<pid>/exe symlink. Unlike comm, a process cannot
// forge this: it is set by the kernel at execve time. The path is resolved in
// the target's mount namespace, so it matches the guest-visible path. Returns
// "" if it cannot be resolved (caller must then treat the app as untrusted).
func procExe(pid uint32) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	// A deleted executable readlinks as "<path> (deleted)"; never trust those.
	if strings.HasSuffix(target, " (deleted)") {
		return ""
	}
	return target
}

// isAppTrusted checks if the process making a request belongs to an app the
// user has blanket-trusted via "perm trust <app>". Trust is keyed on the real
// executable path (procExe), which the guest cannot spoof, instead of the
// freely-settable comm name.
func (s *Supervisor) isAppTrusted(pid uint32) bool {
	if s.brokerClient == nil {
		return false
	}
	exe := procExe(pid)
	if exe == "" {
		return false
	}
	return s.brokerClient.IsAppTrusted(exe)
}

// readBytesFromProcess reads n bytes from a process's virtual memory at addr.
func readBytesFromProcess(pid int, addr uintptr, n int) ([]byte, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer f.Close()

	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, int64(addr)); err != nil {
		return nil, fmt.Errorf("read mem at %x: %w", addr, err)
	}
	return buf, nil
}

// readStringFromProcess reads a null-terminated string from another process's
// virtual memory via /proc/<pid>/mem (requires parent-child relationship).
// Fails if /proc/<pid>/mem is inaccessible (YAMA ptrace_scope > 1, dumpable=0).
func readStringFromProcess(pid int, addr uintptr) (string, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(memPath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", memPath, err)
	}
	defer f.Close()

	var buf [4096]byte
	n, err := f.ReadAt(buf[:], int64(addr))
	if err != nil && n == 0 {
		return "", fmt.Errorf("read mem at %x: %w", addr, err)
	}
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf[:n]), nil
}

// NotifSocketName returns the Unix socket name for seccomp fd transfer.
// It is placed in the XDG_RUNTIME_DIR which is bind-mounted from host into guest,
// making the same path accessible from both parent (host) and child (guest).
func NotifSocketName(xdgRuntime, sessionID string) string {
	// Placed in the "ush" subdir of XDG_RUNTIME_DIR: ush bind-mounts ONLY that
	// subdir into the guest (never the whole runtime dir, which would expose the
	// host session bus), so both sides share this path.
	return filepath.Join(xdgRuntime, "ush", "ush-seccomp-"+sessionID+".sock")
}

// SendNotifFd sends the seccomp notification fd to the parent supervisor
// using SCM_RIGHTS over the socket at socketPath.
// Called from the child process after InstallSeccompNotifyFilter.
func SendNotifFd(notifFd int, socketPath string) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("security: dial notif socket %s: %w", socketPath, err)
	}
	defer conn.Close()

	uc := conn.(*net.UnixConn)
	rights := syscall.UnixRights(notifFd)
	_, _, err = uc.WriteMsgUnix([]byte{0}, rights, nil)
	return err
}

// DialNotifSocket opens a connection to the supervisor socket without
// sending anything yet. Must be called BEFORE installing the seccomp-notify
// filter so the connect() syscall is not itself intercepted.
func DialNotifSocket(socketPath string) (*net.UnixConn, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("security: dial notif socket %s: %w", socketPath, err)
	}
	return conn.(*net.UnixConn), nil
}

// SendNotifFdOverConn sends the seccomp notification fd over an already-open
// Unix connection using SCM_RIGHTS. Use this after DialNotifSocket + filter install.
func SendNotifFdOverConn(notifFd int, conn *net.UnixConn) error {
	defer conn.Close()
	rights := syscall.UnixRights(notifFd)
	_, _, err := conn.WriteMsgUnix([]byte{0}, rights, nil)
	return err
}

// RecvNotifFd listens on socketPath for an incoming SCM_RIGHTS message
// containing the seccomp notification fd. Sets O_CLOEXEC on the received fd
// so it is not accidentally inherited by broker helper processes (zenity, etc.).
// Called from the parent before the child installs the filter.
func RecvNotifFd(socketPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return 0, fmt.Errorf("security: mkdir notif socket dir: %w", err)
	}
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return 0, fmt.Errorf("security: listen %s: %w", socketPath, err)
	}
	defer ln.Close()
	defer os.Remove(socketPath)

	conn, err := ln.Accept()
	if err != nil {
		return 0, fmt.Errorf("security: accept: %w", err)
	}
	defer conn.Close()

	uc := conn.(*net.UnixConn)
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		return 0, fmt.Errorf("security: recv scm_rights: %w", err)
	}

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return 0, fmt.Errorf("security: parse scm: %w", err)
	}

	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return 0, fmt.Errorf("security: parse fds: %w", err)
	}

	notifFd := fds[0]
	// Set O_CLOEXEC to prevent the fd from leaking to broker helper processes.
	if err := unix.SetNonblock(notifFd, false); err == nil {
		unix.FcntlInt(uintptr(notifFd), syscall.F_SETFD, syscall.FD_CLOEXEC)
	}
	return notifFd, nil
}

// SkippedRootPaths are paths excluded from the startup whitelist walk.
// These are either user-controlled (writable) or contain trusted helper binaries
// that must not be directly exec-able by guest processes.
var SkippedRootPaths = []string{
	"/home", "/tmp", "/run", "/proc", "/sys", "/dev",
	"/run/ush/exec", // real apt/dpkg helpers - must not be in whitelist
}

// ShouldSkipForWhitelist returns true if path should be excluded from the
// startup whitelist walk.
func ShouldSkipForWhitelist(path string) bool {
	for _, skip := range SkippedRootPaths {
		if path == skip || strings.HasPrefix(path, skip+"/") {
			return true
		}
	}
	return false
}
