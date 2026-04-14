// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package broker implements the server side of the ush permission broker.
// The broker runs on the host as a user systemd unit and serves the guest over
// a PRIVATE AF_UNIX socket (see transport.go) using a newline-delimited JSON
// protocol. It deliberately does NOT expose itself on the host session bus, so
// the guest never needs access to that bus (and the systemd1 escape it enables).
//
// Methods (over the socket):
//
//	RequestPermission(category, resource, reason, sessionID) -> decision
//	RevokePermission(category, resource)
//	ListPermissions() -> json
//	AllowApp(exe) / DenyApp(exe) / IsAppTrusted(exe) -> bool
package broker

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/singularityos-lab/ush/internal/devpolicy"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/mounthelper"
	"github.com/singularityos-lab/ush/internal/policy"
)

const (
	// PortalBusName et al. are the OPTIONAL desktop-portal interface the broker
	// (a host process) may call to render a native permission dialog. This is a
	// host-to-host D-Bus call inside showDialog; the guest never touches it.
	PortalBusName   = "io.github.singularityos_lab.ush.Portal"
	PortalObjPath   = "/io/github/singularityos_lab/ush/Portal"
	PortalInterface = "io.github.singularityos_lab.ush.Portal1"

	// BusName et al. are the HOST-ONLY management interface, exposed on the
	// session bus for trusted desktop components (the portal/shell) to trust or
	// untrust apps. The guest-facing RequestPermission stays on the private
	// socket; only these three management calls live on D-Bus. This is safe
	// because the guest no longer has the host session bus (its runtime dir is
	// isolated), so only host processes can reach it.
	BusName   = "io.github.singularityos_lab.ush.Broker"
	ObjPath   = "/io/github/singularityos_lab/ush/Broker"
	Interface = "io.github.singularityos_lab.ush.Broker1"
)

// dbusManager exposes the host-only management subset (AllowApp/DenyApp/
// IsAppTrusted) on the session bus for the desktop portal/shell.
type dbusManager struct{ s *Server }

func (d *dbusManager) AllowApp(appExe string) *dbus.Error {
	if err := d.s.allowApp(appExe); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func (d *dbusManager) DenyApp(appExe string) *dbus.Error {
	if err := d.s.denyApp(appExe); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func (d *dbusManager) IsAppTrusted(appExe string) (bool, *dbus.Error) {
	return d.s.isAppTrusted(appExe), nil
}

// TrustDir / UntrustDir / IsDirTrusted / ListDevDirs back the desktop file
// manager's "Share with Linux" gesture. Reachable only on the host session bus
// (the guest has no access to it), so the host UI action is the consent and no
// extra modal dialog is shown.
func (d *dbusManager) TrustDir(path string) *dbus.Error {
	if err := d.s.trustDirConfirmed(path); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func (d *dbusManager) UntrustDir(path string) *dbus.Error {
	if err := d.s.untrustDir(path); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func (d *dbusManager) IsDirTrusted(path string) (bool, *dbus.Error) {
	return d.s.isDirTrusted(path), nil
}

func (d *dbusManager) ListDevDirs() (string, *dbus.Error) {
	return d.s.listDevDirs(), nil
}

// DevShellStatus / SetDevShellEnabled back the desktop "Development" page: it
// queries the policy to decide whether to show the dsh toggle (hidden when the
// policy is "forbidden") and flips the user opt-in.
func (d *dbusManager) DevShellStatus() (string, bool, *dbus.Error) {
	policy, enabled := d.s.devShellStatus()
	return policy, enabled, nil
}

func (d *dbusManager) SetDevShellEnabled(enabled bool) *dbus.Error {
	if err := d.s.setDevShellEnabled(enabled); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

// StartManagementBus registers the host-only management interface on the session
// bus. Best-effort: in a headless environment with no session bus it just logs
// and returns; the socket transport keeps working regardless.
func (s *Server) StartManagementBus() {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		ushlog.Info("broker: no session bus, management D-Bus interface disabled", "err", err)
		return
	}
	reply, err := conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		ushlog.Info("broker: management D-Bus name unavailable (already running?)")
		conn.Close()
		return
	}
	mgr := &dbusManager{s: s}
	conn.Export(mgr, dbus.ObjectPath(ObjPath), Interface)
	conn.Export(introspect.Introspectable(managementIntrospectXML), dbus.ObjectPath(ObjPath),
		"org.freedesktop.DBus.Introspectable")
	ushlog.Info("broker: host management D-Bus interface active", "bus", BusName)
}

var managementIntrospectXML = `
<node>
  <interface name="io.github.singularityos_lab.ush.Broker1">
    <method name="AllowApp"><arg name="appExe" type="s" direction="in"/></method>
    <method name="DenyApp"><arg name="appExe" type="s" direction="in"/></method>
    <method name="IsAppTrusted">
      <arg name="appExe" type="s" direction="in"/>
      <arg name="trusted" type="b" direction="out"/>
    </method>
    <method name="TrustDir"><arg name="path" type="s" direction="in"/></method>
    <method name="UntrustDir"><arg name="path" type="s" direction="in"/></method>
    <method name="IsDirTrusted">
      <arg name="path" type="s" direction="in"/>
      <arg name="trusted" type="b" direction="out"/>
    </method>
    <method name="ListDevDirs"><arg name="dirs" type="s" direction="out"/></method>
    <method name="DevShellStatus">
      <arg name="policy" type="s" direction="out"/>
      <arg name="enabled" type="b" direction="out"/>
    </method>
    <method name="SetDevShellEnabled"><arg name="enabled" type="b" direction="in"/></method>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect"><arg name="xml_data" type="s" direction="out"/></method>
  </interface>
</node>`

// Server is the host-side broker. It listens on a private AF_UNIX socket.
type Server struct {
	mu         sync.Mutex
	listener   net.Listener
	policy     *policy.Engine
	auditLog   *AuditLog
	inflight   map[string]*inflightPermission
	auto       *autoDecider // non-interactive decision mode (testing/CI)
	storageDir string       // for the dsh opt-in marker (see internal/devpolicy)
}

type inflightPermission struct {
	done     chan struct{}
	decision string
}

// NewServer creates a new broker server.
func NewServer(storageDir string) (*Server, error) {
	eng, err := policy.NewEngine(filepath.Join(storageDir, "policy.json"))
	if err != nil {
		return nil, fmt.Errorf("broker: policy engine: %w", err)
	}

	audit, err := NewAuditLog(filepath.Join(storageDir, "audit"))
	if err != nil {
		return nil, fmt.Errorf("broker: audit log: %w", err)
	}

	return &Server{
		policy:     eng,
		auditLog:   audit,
		inflight:   make(map[string]*inflightPermission),
		auto:       newAutoDecider(),
		storageDir: storageDir,
	}, nil
}
