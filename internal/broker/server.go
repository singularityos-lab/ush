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

// isAppTrusted checks if an app has been granted blanket permission.
func (s *Server) isAppTrusted(appName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	appKey := "app:" + appName
	decision, ok := s.policy.Check(policy.Category(appKey), "*")
	return ok && decision == policy.DecisionAllow
}

// devDirCategory is the policy category under which trusted developer
// directories are stored. A trusted dir gets full host access from the guest
// (executables and VCS hooks run on the host), so the grant always requires
// explicit host-side confirmation, exactly like app trust.
const devDirCategory policy.Category = "devdir"

// trustDir grants a directory full host access from the guest, AFTER a host-side
// confirmation. This is the path used by the guest shell's `perm trust-dir`,
// where the requester is the untrusted guest and the dialog is the security gate.
func (s *Server) trustDir(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	if !s.confirmDialog(
		"USH - Trust developer directory",
		fmt.Sprintf("Give the sandbox FULL host access to this directory?\n\n%s\n\n"+
			"Executables and git hooks the sandbox writes here will be able to run "+
			"on your host. Only do this for directories you actively develop in.",
			dialogSafe(path)),
	) {
		ushlog.Warn("broker: dir trust denied by user", "path", path)
		return fmt.Errorf("trust not confirmed by user")
	}
	return s.trustDirConfirmed(path)
}

// trustDirConfirmed persists a directory trust WITHOUT a confirmation dialog. It
// is only reachable from the HOST-ONLY management D-Bus interface (the desktop
// file manager's "Share with Linux"): that caller is already a trusted host UI
// and the guest cannot reach the session bus, so the host UI gesture IS the
// consent. The guest socket path never calls this; it goes through trustDir.
func (s *Server) trustDirConfirmed(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	s.mu.Lock()
	s.policy.Set(devDirCategory, path, policy.DecisionAllow)
	err := s.policy.Save()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	ushlog.Info("broker: developer directory trusted", "path", path)

	// Apply it live to any running guest: the mount helper attaches the folder
	// without a restart. Best-effort; if no helper answers, `restart` applies it.
	mounthelper.Notify(runtimeDir(), path)
	return nil
}

// runtimeDir returns $XDG_RUNTIME_DIR (or the conventional fallback) where the
// per-session mount-helper sockets live.
func runtimeDir() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return rt
	}
	return filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
}

// requestDevShell asks the user, host-side, to open the developer environment
// (dsh). The guest can call it but cannot answer it: the dialog is the gate that
// stops sandboxed code from escalating itself into the unlocked dev world.
func (s *Server) requestDevShell() bool {
	// Policy gate first: a guest may ask, but the image/managed policy and the
	// user opt-in decide. The guest cannot forge either (the image policy is in
	// the immutable rootfs; the opt-in marker is in the host-owned storage dir).
	if devpolicy.Evaluate(s.storageDir) != devpolicy.Allow {
		ushlog.Info("broker: dev shell request refused by policy")
		return false
	}
	return s.confirmDialog(
		"USH - Open developer environment",
		"Open the developer environment (dsh)?\n\n"+
			"It unlocks containers (podman/distrobox), builds and an open network. "+
			"It is NOT a security sandbox: code you run there has a real developer "+
			"machine on your account.")
}

// devShellStatus reports the image policy and whether dsh is enabled now, for
// the desktop "Development" page (it hides the toggle when not permitted).
func (s *Server) devShellStatus() (policy string, enabled bool) {
	return devpolicy.Status(s.storageDir)
}

// setDevShellEnabled flips the user opt-in. Refused if the image policy forbids
// dsh, so the desktop cannot bypass a managed image.
func (s *Server) setDevShellEnabled(on bool) error {
	return devpolicy.SetUserEnabled(s.storageDir, on)
}

// isDirTrusted reports whether path is at or below a trusted developer directory.
func (s *Server) isDirTrusted(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	path = strings.TrimRight(path, "/")
	for _, r := range s.policy.List() {
		if r.Category != devDirCategory || r.Decision != policy.DecisionAllow {
			continue
		}
		d := strings.TrimRight(r.Resource, "/")
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// untrustDir revokes a directory's trust.
func (s *Server) untrustDir(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy.Remove(devDirCategory, path)
	if err := s.policy.Save(); err != nil {
		return err
	}
	ushlog.Info("broker: developer directory untrusted", "path", path)
	return nil
}

// listDevDirs returns the trusted developer directories as a JSON array.
func (s *Server) listDevDirs() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var dirs []string
	for _, r := range s.policy.List() {
		if r.Category == devDirCategory && r.Decision == policy.DecisionAllow {
			dirs = append(dirs, r.Resource)
		}
	}
	data, _ := json.Marshal(dirs)
	return string(data)
}

// dialogSafe sanitizes a guest-controlled string before it is rendered in a
// host-side dialog or terminal. The guest fully controls category/resource/
// reason/app over the control socket; without this a value like
// "harmless\n\nClick Grant to continue" (or a raw ANSI escape such as \033[2J)
// could forge the dialog text to socially engineer a grant, or corrupt the host
// terminal. Strips every ASCII control character (newlines, tabs, ESC, NUL) and
// caps the length so dialog text is a single, bounded, inert line. Policy keys
// keep the raw value; only the rendered copy is sanitized.
func dialogSafe(in string) string {
	const max = 256
	var b strings.Builder
	for _, r := range in {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len(out) > max {
		out = out[:max] + "..."
	}
	return out
}

// showDialog shows the permission request dialog to the user.
// Tries the ush Portal D-Bus interface first (native DE integration),
// then falls back to zenity, kdialog, or terminal prompt.
func (s *Server) showDialog(category, resource, reason string) string {
	// Non-interactive mode: decide from the scripted policy and skip all GUIs.
	// Uses the raw values so scripted rule matching stays exact.
	if s.auto != nil && s.auto.enabled {
		return s.auto.decide(category, resource, reason)
	}

	// Everything below is user-facing: sanitize the guest-controlled strings so
	// they cannot forge the dialog body or inject terminal escapes.
	category = dialogSafe(category)
	resource = dialogSafe(resource)
	reason = dialogSafe(reason)

	if decision := s.portalDialog(category, resource, reason); decision != "" {
		return decision
	}

	msg := fmt.Sprintf(
		"USH - Permission request\n\nCategory: %s\nResource: %s",
		category, resource,
	)
	if reason != "" {
		msg += "\n\nReason: " + reason
	}

	if _, err := exec.LookPath("zenity"); err == nil {
		return s.zenityDialog(msg)
	}

	if _, err := exec.LookPath("kdialog"); err == nil {
		return s.kdialogDialog(msg)
	}

	return s.terminalDialog(category, resource, reason)
}

// confirmDialog asks the user a yes/no question and returns true only on an
// explicit affirmative answer. Everything else (cancel, error, no dialog tool,
// EOF on the terminal) is treated as "no" so the default is always safe. Used
// to gate privileged broker operations that the sandboxed guest can invoke.
func (s *Server) confirmDialog(title, msg string) bool {
	// Non-interactive mode: answer from the scripted confirm verdict.
	if s.auto != nil && s.auto.enabled {
		return s.auto.confirmVerdict("confirm", title)
	}

	// Prefer the desktop portal (native dialog), fall back to zenity/kdialog/term
	// when it is absent (headless/CI).
	if ok, served := s.portalConfirm(title, msg); served {
		return ok
	}

	if _, err := exec.LookPath("zenity"); err == nil {
		err := exec.Command("zenity", "--question",
			"--title="+title, "--text="+msg,
			"--ok-label=Grant", "--cancel-label=Deny",
			"--width=500").Run()
		return err == nil // zenity exits 0 only when the user confirms
	}
	if _, err := exec.LookPath("kdialog"); err == nil {
		err := exec.Command("kdialog", "--title", title, "--yesno", msg).Run()
		return err == nil
	}

	fmt.Printf("\n\033[1;33m[USH broker]\033[0m %s\n%s\n", title, msg)
	fmt.Printf("Type 'yes' to confirm: ")
	var answer string
	fmt.Scanln(&answer)
	return strings.EqualFold(strings.TrimSpace(answer), "yes")
}

// portalConfirm asks the desktop portal to render a yes/no confirmation via
// io.github.singularityos_lab.ush.Portal1.ShowConfirm. served is false when the portal
// is unavailable, so the caller falls back to zenity/kdialog/terminal.
func (s *Server) portalConfirm(title, body string) (result bool, served bool) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return false, false
	}
	defer conn.Close()
	obj := conn.Object(PortalBusName, dbus.ObjectPath(PortalObjPath))
	call := obj.Call(PortalInterface+".ShowConfirm", 0, title, body)
	if call.Err != nil {
		return false, false
	}
	if err := call.Store(&result); err != nil {
		return false, false
	}
	return result, true
}

// portalDialog calls the ush Portal D-Bus interface.
// A DE that implements io.github.singularityos_lab.ush.Portal1 can show
// a native permission dialog. Returns empty string if the portal
// is unavailable or the call fails (fallback path).
func (s *Server) portalDialog(category, resource, reason string) string {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return ""
	}
	defer conn.Close()

	obj := conn.Object(PortalBusName, dbus.ObjectPath(PortalObjPath))
	var decision string
	call := obj.Call(PortalInterface+".ShowPermission", 0,
		category, resource, reason,
	)
	if err := call.Store(&decision); err != nil {
		return ""
	}

	switch decision {
	case "allow", "allow_session", "allow_always", "deny":
		return decision
	default:
		return ""
	}
}

func (s *Server) zenityDialog(msg string) string {
	args := []string{"--list",
		"--title=USH - Permission request",
		"--text=" + msg,
		"--column=Choice",
		"--column=Description",
		"allow", "Allow this time",
		"allow_session", "Allow for this session",
		"allow_always", "Always allow this resource",
		"deny", "Deny",
		"--width=500", "--height=350",
	}

	cmd := exec.Command("zenity", args...)

	out, err := cmd.Output()
	if err != nil {
		return "deny"
	}

	choice := strings.TrimSpace(string(out))
	if choice == "" {
		return "deny"
	}
	return choice
}

func (s *Server) kdialogDialog(msg string) string {
	choices := "allow:Allow this time|allow_session:Allow for session|allow_always:Always allow this resource|deny:Deny"
	cmd := exec.Command("kdialog", "--menu", msg, choices)

	out, err := cmd.Output()
	if err != nil {
		return "deny"
	}
	return strings.TrimSpace(string(out))
}

func (s *Server) terminalDialog(category, resource, reason string) string {
	fmt.Printf("\n\033[1;33m[USH broker]\033[0m Permission request\n")
	fmt.Printf("  Category: %s\n", category)
	fmt.Printf("  Resource: %s\n", resource)
	if reason != "" {
		fmt.Printf("  Reason:   %s\n", reason)
	}
	fmt.Printf("\n  [1] Allow this time\n")
	fmt.Printf("  [2] Allow for this session\n")
	fmt.Printf("  [3] Always allow this resource\n")
	fmt.Printf("  [4] Deny (default)\n")
	fmt.Printf("\nChoice: ")

	var choice string
	fmt.Scanln(&choice)

	switch strings.TrimSpace(choice) {
	case "1":
		return "allow"
	case "2":
		return "allow_session"
	case "3":
		return "allow_always"
	default:
		return "deny"
	}
}

// AuditLog manages the broker audit log.
type AuditLog struct {
	dir  string
	mu   sync.Mutex
	file *os.File
	date string // YYYY-MM-DD of the currently open file, for rotation
}

// AuditEntry is a record in the audit log.
type AuditEntry struct {
	Timestamp time.Time `json:"ts"`
	SessionID string    `json:"session"`
	Category  string    `json:"category"`
	Resource  string    `json:"resource"`
	Scope     string    `json:"scope,omitempty"`
	Decision  string    `json:"decision"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason,omitempty"`
}

// NewAuditLog creates a new audit log.
func NewAuditLog(dir string) (*AuditLog, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	a := &AuditLog{dir: dir}
	if err := a.openFile(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AuditLog) openFile() error {
	date := time.Now().Format("2006-01-02")
	path := filepath.Join(a.dir, date+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	a.file = f
	a.date = date
	return nil
}

// Write writes a record to the log, rotating to a new dated file when the day
// changes so a long-running broker does not keep appending to the first day.
func (a *AuditLog) Write(entry AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if today := time.Now().Format("2006-01-02"); today != a.date {
		if a.file != nil {
			a.file.Close()
		}
		if err := a.openFile(); err != nil {
			return
		}
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	a.file.Write(append(data, '\n'))
}

// Close closes the log.
func (a *AuditLog) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		a.file.Close()
	}
}
