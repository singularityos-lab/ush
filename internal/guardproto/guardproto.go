// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package guardproto defines the wire types shared between ush and the
// Singularity Guard daemon (singd). ush produces a behavioural telemetry feed
// (exec/connect/open/mount events from the seccomp-notify supervisor) and acts
// as a thin client for the guard's on-demand scan / status / quarantine
// commands. singd lives in a separate repository and imports this package too.
//
// This package has no dependencies beyond the standard library so it can be
// vendored by singd without pulling in the rest of ush.
package guardproto

import (
	"os"
	"path/filepath"
	"strconv"
)

// EventKind classifies a telemetry event emitted by the ush supervisor.
type EventKind string

const (
	EventExec    EventKind = "exec"    // execve / execveat
	EventConnect EventKind = "connect" // outbound connect() to a non-local address
	EventOpen    EventKind = "open"    // openat() of a sensitive /dev path
	EventMount   EventKind = "mount"   // mount() inside the guest
)

// Event is a single behavioural telemetry record. It is the EDR feed singd's
// behavioural correlator consumes; ush emits it best-effort (events may be
// dropped under load, detection must tolerate gaps, never block a syscall).
type Event struct {
	Time    string    `json:"time"`              // RFC3339 timestamp
	Kind    EventKind `json:"kind"`              // event class
	PID     uint32    `json:"pid"`               // guest PID that triggered it
	Comm    string    `json:"comm,omitempty"`    // short command name
	Path    string    `json:"path,omitempty"`    // exec/open/mount target (guest path)
	Dest    string    `json:"dest,omitempty"`    // connect destination "ip:port"
	Detail  string    `json:"detail,omitempty"`  // free-form extra context
	Session string    `json:"session,omitempty"` // ush session id, if known
}

// Request is a control command sent by the ush shell builtins (scan / guard /
// quarantine) to singd over the control socket.
type Request struct {
	Cmd  string   `json:"cmd"`            // "scan" | "status" | "quarantine"
	Args []string `json:"args,omitempty"` // sub-arguments (e.g. a path, "list")
}

// Response is singd's reply to a Request. Output is already formatted for
// terminal display so the shell can print it verbatim.
type Response struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// runtimeDir returns the best base directory for guard sockets.
func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
}

// EventsSocket is the Unix socket ush writes telemetry events to (JSON lines).
// Overridable via USH_GUARD_EVENTS_SOCK so singd and ush can agree at runtime.
func EventsSocket() string {
	if s := os.Getenv("USH_GUARD_EVENTS_SOCK"); s != "" {
		return s
	}
	return filepath.Join(runtimeDir(), "singd-events.sock")
}

// ControlSocket is the Unix socket the shell builtins use to talk to singd.
// Overridable via USH_GUARD_CTL_SOCK.
func ControlSocket() string {
	if s := os.Getenv("USH_GUARD_CTL_SOCK"); s != "" {
		return s
	}
	return filepath.Join(runtimeDir(), "singd-control.sock")
}
