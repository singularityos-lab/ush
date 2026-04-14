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

// Start binds the broker's private control socket and serves it.
func (s *Server) Start() error {
	sockPath := SocketPath()
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		return fmt.Errorf("broker: socket dir: %w", err)
	}
	// A stale socket from a previous run blocks Listen.
	os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("broker: listen %s: %w", sockPath, err)
	}
	// Owner-only: only the same uid (the guest maps to it) may connect.
	if err := os.Chmod(sockPath, 0600); err != nil {
		ushlog.Warn("broker: chmod socket", "err", err)
	}
	s.listener = ln
	go s.serve()

	ushlog.Info("broker: started", "socket", sockPath)
	return nil
}

// Stop closes the broker.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.auditLog.Close()
}

// requestPermission returns the decision: "allow", "deny", "allow_session",
// "allow_always".
func (s *Server) requestPermission(
	category, resource, reason, sessionID string,
) string {
	ushlog.Info("broker: permission request",
		"category", category,
		"resource", resource,
		"session", sessionID,
	)

	if decision, ok := s.policy.Check(policy.Category(category), resource); ok {
		s.auditLog.Write(AuditEntry{
			Timestamp: time.Now(),
			SessionID: sessionID,
			Category:  category,
			Resource:  resource,
			Decision:  string(decision),
			Source:    "policy_cache",
		})
		ushlog.Info("broker: decision from policy cache", "decision", decision)
		return string(decision)
	}

	scope := policy.SuggestScope(policy.Category(category), resource)
	if decision, ok := s.policy.Check(policy.Category(category), scope.Resource); ok {
		s.auditLog.Write(AuditEntry{
			Timestamp: time.Now(),
			SessionID: sessionID,
			Category:  category,
			Resource:  resource,
			Scope:     scope.Resource,
			Decision:  string(decision),
			Source:    "policy_cache",
		})
		ushlog.Info("broker: decision from scoped policy cache", "decision", decision)
		return string(decision)
	}

	if decision, waited := s.waitForInflightPermission(category, resource, scope, sessionID); waited {
		return decision
	}

	inflightKey := permissionInflightKey(category, scope.Resource)
	inflight := &inflightPermission{done: make(chan struct{})}
	s.mu.Lock()
	s.inflight[inflightKey] = inflight
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		inflight.decision = finalDecisionForWaiters(inflight.decision)
		delete(s.inflight, inflightKey)
		close(inflight.done)
		s.mu.Unlock()
	}()

	// Another request may have persisted the scope while this one was registering.
	if decision, ok := s.policy.Check(policy.Category(category), resource); ok {
		inflight.decision = string(decision)
		return string(decision)
	}

	dialogReason := scopedReason(reason, resource, scope)

	// Show user dialog.
	decision := s.showDialog(category, scope.Resource, dialogReason)
	inflight.decision = decision

	// Save based on the response.
	switch decision {
	case "allow_session":
		// Cache in memory only - not persisted to disk.
		// Future requests covered by the suggested scope skip the dialog.
		s.policy.Set(policy.Category(category), scope.Resource, policy.DecisionAllow)
	case "allow_always":
		s.policy.Set(policy.Category(category), scope.Resource, policy.DecisionAllow)
		s.policy.Save()
	case "deny_always":
		s.policy.Set(policy.Category(category), scope.Resource, policy.DecisionDeny)
		s.policy.Save()
		decision = "deny"
	}

	s.auditLog.Write(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Category:  category,
		Resource:  resource,
		Scope:     scope.Resource,
		Decision:  decision,
		Source:    "user_dialog",
		Reason:    dialogReason,
	})

	ushlog.Info("broker: user decision", "decision", decision)
	return decision
}

func (s *Server) waitForInflightPermission(category, resource string, scope policy.Scope, sessionID string) (string, bool) {
	key := permissionInflightKey(category, scope.Resource)
	s.mu.Lock()
	inflight := s.inflight[key]
	s.mu.Unlock()
	if inflight == nil {
		return "", false
	}

	<-inflight.done

	if decision, ok := s.policy.Check(policy.Category(category), resource); ok {
		s.auditLog.Write(AuditEntry{
			Timestamp: time.Now(),
			SessionID: sessionID,
			Category:  category,
			Resource:  resource,
			Scope:     scope.Resource,
			Decision:  string(decision),
			Source:    "inflight_policy_cache",
		})
		return string(decision), true
	}

	decision := finalDecisionForWaiters(inflight.decision)
	s.auditLog.Write(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Category:  category,
		Resource:  resource,
		Scope:     scope.Resource,
		Decision:  decision,
		Source:    "inflight_dialog",
	})
	return decision, true
}

func permissionInflightKey(category, resource string) string {
	return category + "\x00" + resource
}

func finalDecisionForWaiters(decision string) string {
	switch decision {
	case "allow_always", "allow_session":
		return "allow"
	case "":
		return "deny"
	default:
		return decision
	}
}

func scopedReason(reason, requested string, scope policy.Scope) string {
	if scope.Resource == requested {
		return reason
	}

	detail := fmt.Sprintf("Requested resource: %s\nSuggested scope: %s", requested, scope.Resource)
	if scope.Exact {
		detail += "\nScope is exact because the resource is sensitive or high-risk."
	}
	if reason == "" {
		return detail
	}
	return reason + "\n\n" + detail
}

// RevokePermission revokes a permanent permission. Removing a rule can also
// remove a "deny", which would re-open a previously blocked resource, so a
// guest must not be able to do this silently: it requires user confirmation.
func (s *Server) revokePermission(category, resource string) error {
	if !s.confirmDialog(
		"USH - Revoke permission",
		fmt.Sprintf("Remove the saved permission rule for:\n\nCategory: %s\nResource: %s",
			dialogSafe(category), dialogSafe(resource)),
	) {
		ushlog.Warn("broker: revoke denied by user", "category", category, "resource", resource)
		return fmt.Errorf("revoke not confirmed by user")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.policy.Remove(policy.Category(category), resource)
	if err := s.policy.Save(); err != nil {
		return err
	}

	ushlog.Info("broker: permission revoked", "category", category, "resource", resource)
	return nil
}

// listPermissions returns the list of permissions as JSON.
func (s *Server) listPermissions() (string, error) {
	perms := s.policy.List()
	data, err := json.Marshal(perms)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// AllowApp grants all permissions for a specific application, keyed on the
// application's absolute executable path (the supervisor matches against the
// kernel-maintained /proc/<pid>/exe, which a guest cannot spoof).
//
// This grant disables future prompts for that binary, so a compromised guest
// must not be able to hand it to itself over the control socket: it ALWAYS
// requires explicit user confirmation through a dialog before it is persisted.
func (s *Server) allowApp(appExe string) error {
	if !s.confirmDialog(
		"USH - Trust application",
		fmt.Sprintf("Grant ALL permissions to this application?\n\n%s\n\n"+
			"It will no longer prompt for network, device or filesystem access.",
			dialogSafe(appExe)),
	) {
		ushlog.Warn("broker: app trust denied by user", "exe", appExe)
		return fmt.Errorf("trust not confirmed by user")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	appKey := "app:" + appExe
	s.policy.Set(policy.Category(appKey), "*", policy.DecisionAllow)
	if err := s.policy.Save(); err != nil {
		return err
	}

	ushlog.Info("broker: app trusted", "exe", appExe)
	return nil
}

// denyApp removes the trust for an application.
func (s *Server) denyApp(appName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	appKey := "app:" + appName
	s.policy.Remove(policy.Category(appKey), "*")
	if err := s.policy.Save(); err != nil {
		return err
	}

	ushlog.Info("broker: app untrusted", "app", appName)
	return nil
}
