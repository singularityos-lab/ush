// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// sdb.go backs the desktop Settings control for the debug bridge (sdbd).
//
// Invariant: the reported state is always the one OBSERVED after acting, never
// the one requested. The broker probes sdbd's own control socket, so a start
// that did not take or a stop that did not stop shows as such. The rest of this
// file relies on that invariant without restating it.
//
// Observation is independent of the init system: a serving sdbd accepts control
// connections, a stopped one does not. Actuation is not: start/stop goes through
// sdbService, whose active implementation is atomSdbService (atomctl.go, writes
// the opt-in marker and drives sinit). unconfiguredSdbService is the fallback for
// a build with no init control seam and refuses every call.
package broker

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// defaultSdbControlSocket is sdbd's local control socket. Its reachability is
// the ground truth for whether the bridge is serving.
const defaultSdbControlSocket = "/run/sinty-sdb.sock"

// sdbProbeTimeout bounds one reachability probe.
const sdbProbeTimeout = 2 * time.Second

// sdbSettleTimeout bounds how long the broker waits for the service to reach the
// requested state before reporting what it actually observes. It is a var only
// so tests can shorten the wait on the paths that never settle.
var (
	sdbSettleTimeout = 5 * time.Second
	sdbSettlePoll    = 100 * time.Millisecond
)

// User-facing messages, displayed verbatim by the desktop.
const (
	msgSdbNotInstalled  = "The debug bridge is not installed on this image."
	msgSdbStateUnknown  = "The state of the debug bridge could not be determined."
	msgSdbRemoteRefused = "The debug bridge cannot be switched on or off from a remote host."
	msgSdbStartFailed   = "The debug bridge did not start. It is not accepting connections."
	msgSdbStopFailed    = "The debug bridge could not be stopped and may still be accepting connections."
	msgSdbOn            = "The debug bridge is on."
	msgSdbOff           = "The debug bridge is off."
	msgSdbNotControlled = "The debug bridge cannot be controlled on this system."
)

func sdbControlSocketPath() string {
	if p := os.Getenv("USH_SDB_SOCK"); p != "" {
		return p
	}
	return defaultSdbControlSocket
}

// sdbService is the seam through which the broker actuates the sdbd service.
// It is an interface rather than a function so the two questions it answers
// stay together: whether the service exists at all, and how to switch it.
type sdbService interface {
	// Present reports whether the service is installed and controllable.
	Present() (bool, error)
	// SetEnabled starts and enables, or stops and disables, the service NOW.
	// It must act live: a change that only takes effect at next boot is a
	// failure, because the caller is closing a listener that is open today.
	SetEnabled(on bool) error
}

// errSdbServiceUnconfigured is returned by the placeholder implementation. It is
// an error, not a silent no-op, so a system with no service control fails closed
// and says so.
var errSdbServiceUnconfigured = errors.New(
	"sdb service control is not configured for this init system")

type unconfiguredSdbService struct{}

func (unconfiguredSdbService) Present() (bool, error) {
	return false, errSdbServiceUnconfigured
}

func (unconfiguredSdbService) SetEnabled(bool) error {
	return errSdbServiceUnconfigured
}

// sdbControl is the active implementation: the init's control socket (see
// atomctl.go). It is a package var only so tests can substitute a fake.
var sdbControl sdbService = atomSdbService{}

// sdbObservedActive probes sdbd's control socket. known is false when the probe
// cannot establish either answer (e.g. the socket exists but the broker cannot
// connect); callers treat that as fail-closed.
func sdbObservedActive() (active bool, known bool) {
	conn, err := net.DialTimeout("unix", sdbControlSocketPath(), sdbProbeTimeout)
	if err == nil {
		conn.Close()
		return true, true
	}
	// No socket, or nothing listening on it, is a definite "not serving".
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return false, true
	}
	return false, false
}

// sdbSettle waits briefly for the service to reach want before probing, since
// start/stop are not instantaneous and an immediate probe catches a transient
// state.
func sdbSettle(want bool) (active bool, known bool) {
	deadline := time.Now().Add(sdbSettleTimeout)
	for {
		active, known = sdbObservedActive()
		if known && active == want {
			return active, known
		}
		if time.Now().After(deadline) {
			return active, known
		}
		time.Sleep(sdbSettlePoll)
	}
}

// sdbStatus reports whether the control should be offered at all, and the state
// observed right now.
func (s *Server) sdbStatus() (available bool, active bool, message string) {
	active, known := sdbObservedActive()

	present, err := sdbControl.Present()
	if err != nil {
		ushlog.Info("broker: sdb service state undetermined", "err", err)
		return false, activeOrUnknown(active, known), msgSdbNotControlled
	}
	if !present {
		return false, activeOrUnknown(active, known), msgSdbNotInstalled
	}
	if !known {
		return false, false, msgSdbStateUnknown
	}
	if active {
		return true, true, msgSdbOn
	}
	return true, false, msgSdbOff
}

// activeOrUnknown never reports "active" on the strength of a probe that failed
// to establish anything.
func activeOrUnknown(active, known bool) bool {
	return known && active
}

// setSdbEnabled switches the bridge and reports the observed state. ok is true
// only when the observed state matches the request; a stop that leaves the
// listener up returns ok=false, active=true, so the desktop keeps the switch on.
func (s *Server) setSdbEnabled(enabled bool, origin Origin, peer peerIdentity) (ok bool, active bool, message string) {
	// Neither direction is available remotely: a remote host must not bootstrap
	// the bridge on, nor flip it off for the local user.
	if origin.Remote {
		ushlog.Warn("broker: sdb switch refused, request is not local",
			"origin", origin.auditValue())
		s.auditSdb(enabled, "deny", "remote_origin_refused", origin)
		observed, known := sdbObservedActive()
		return false, activeOrUnknown(observed, known), msgSdbRemoteRefused
	}

	if !peer.isOwner(uint32(os.Getuid())) {
		ushlog.Warn("broker: sdb switch from unverified peer", "peer_known", peer.known)
		s.auditSdb(enabled, "deny", "peer_unverified", origin)
		observed, known := sdbObservedActive()
		return false, activeOrUnknown(observed, known), msgPeerUnverified
	}

	present, err := sdbControl.Present()
	if err != nil {
		s.auditSdb(enabled, "error", "service_undetermined", origin)
		return false, pessimisticActive(enabled), msgSdbNotControlled
	}
	if !present {
		s.auditSdb(enabled, "deny", "service_absent", origin)
		return false, pessimisticActive(enabled), msgSdbNotInstalled
	}
	switchErr := sdbControl.SetEnabled(enabled)
	if switchErr != nil {
		ushlog.Warn("broker: sdb switch failed", "enable", enabled, "err", switchErr)
	}

	// Report the observed state, not the command's exit: a command that exits 0
	// having changed nothing is the case this catches.
	observed, known := sdbSettle(enabled)
	if !known {
		s.auditSdb(enabled, "error", "state_unknown", origin)
		return false, pessimisticActive(enabled), msgSdbStateUnknown
	}
	if observed != enabled {
		s.auditSdb(enabled, "error", "state_mismatch", origin)
		if enabled {
			return false, observed, msgSdbStartFailed
		}
		return false, observed, msgSdbStopFailed
	}
	if switchErr != nil {
		// The service reached the requested state even though the command
		// complained. Trust the observation, but do not call it a clean success.
		s.auditSdb(enabled, "allow", "state_reached_with_error", origin)
		return true, observed, stateMessage(observed)
	}

	s.auditSdb(enabled, "allow", "switched", origin)
	return true, observed, stateMessage(observed)
}

// pessimisticActive is the answer for an untrustworthy observation: never the
// reassuring one (a start reports "not running", a stop "may still be running").
func pessimisticActive(requested bool) bool {
	return !requested
}

func stateMessage(active bool) string {
	if active {
		return msgSdbOn
	}
	return msgSdbOff
}

func (s *Server) auditSdb(enabled bool, decision, source string, origin Origin) {
	action := "disable"
	if enabled {
		action = "enable"
	}
	s.auditLog.Write(AuditEntry{
		Timestamp: time.Now(),
		Category:  "sdb",
		Resource:  "debug-bridge:" + action,
		Decision:  decision,
		Source:    source,
		Origin:    origin.auditValue(),
	})
}
