// SPDX-License-Identifier: GPL-3.0-or-later

package broker

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// mockAgent stands in for atom-recovery: an HTTP server on a unix socket. It
// records every call so a test can assert not just the answer but whether the
// privileged agent was reached at all, which is what separates "refused outright"
// from "prompted and then denied".
type mockAgent struct {
	mu    sync.Mutex
	calls []string
	armed []bool

	status   int
	body     string
	lockBody LockState
}

func (m *mockAgent) record(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, path)
}

func (m *mockAgent) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockAgent) lastArmed() (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.armed) == 0 {
		return false, false
	}
	return m.armed[len(m.armed)-1], true
}

// startMockAgent serves the mock on a unix socket and points the broker at it.
func startMockAgent(t *testing.T, m *mockAgent) {
	t.Helper()

	// A unix socket path is capped near 108 bytes, so keep it short rather than
	// nesting under the test's temp dir name.
	dir, err := os.MkdirTemp("", "ush-agent")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	sock := filepath.Join(dir, "a.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/lock-state", func(w http.ResponseWriter, r *http.Request) {
		m.record("/lock-state")
		if m.status != 0 && m.status != http.StatusOK {
			w.WriteHeader(m.status)
			return
		}
		if m.body != "" {
			w.Write([]byte(m.body))
			return
		}
		json.NewEncoder(w).Encode(m.lockBody)
	})
	mux.HandleFunc("/arm-unlock", func(w http.ResponseWriter, r *http.Request) {
		m.record("/arm-unlock")
		var req struct {
			Armed bool `json:"armed"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		m.armed = append(m.armed, req.Armed)
		m.mu.Unlock()

		if m.status != 0 && m.status != http.StatusOK {
			w.WriteHeader(m.status)
			return
		}
		if m.body != "" {
			w.Write([]byte(m.body))
			return
		}
		json.NewEncoder(w).Encode(armReply{OK: true, Message: "consent updated"})
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
		os.RemoveAll(dir)
	})

	t.Setenv("USH_ATOM_RECOVERY_SOCK", sock)
}

// testPIN is the PIN the mock recoverd accepts. It is a test fixture, not a
// credential of any kind.
const testPIN = "1234"

// mockRecoverd stands in for sinty-recoverd's verify action, speaking the same
// newline delimited protocol: verify, uid, pin.
type mockRecoverd struct {
	mu      sync.Mutex
	seen    int
	lines   [][]string
	reply   string
	literal bool
}

func (m *mockRecoverd) attempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen
}

func (m *mockRecoverd) lastRequest() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.lines) == 0 {
		return nil
	}
	return m.lines[len(m.lines)-1]
}

func startMockRecoverd(t *testing.T, m *mockRecoverd) {
	t.Helper()

	dir, err := os.MkdirTemp("", "ush-recoverd")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	sock := filepath.Join(dir, "r.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				var got []string
				for i := 0; i < 3; i++ {
					line, err := r.ReadString('\n')
					if err != nil && line == "" {
						return
					}
					got = append(got, strings.TrimRight(line, "\r\n"))
				}
				m.mu.Lock()
				m.seen++
				m.lines = append(m.lines, got)
				literal, reply := m.literal, m.reply
				m.mu.Unlock()

				if literal {
					c.Write([]byte(reply + "\n"))
					return
				}
				if len(got) == 3 && got[0] == "verify" && got[2] == testPIN {
					c.Write([]byte("OK\n"))
					return
				}
				c.Write([]byte("FAIL\n"))
			}(conn)
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		os.RemoveAll(dir)
	})

	t.Setenv("USH_RECOVERD_SOCK", sock)
}

// localPeer is the credentials the kernel reports for a same-user connection.
func localPeer() peerIdentity {
	return peerIdentity{known: true, uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), pid: 1}
}

func newBootloaderServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Stop)
	return srv
}

// Negative proof: arming is refused for a remote origin, and the privileged
// agent is never contacted. The environment is set up to say yes to everything
// (auto mode, confirm=yes) so the refusal cannot be credited to the dialog.
func TestArmUnlockRefusedFromRemoteOrigin(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	t.Setenv("USH_BROKER_CONFIRM", "yes")

	cases := []struct {
		name   string
		origin string
	}{
		{"paired host", SDBOrigin("workstation")},
		{"unlabelled bridge", SDBOrigin("")},
		{"unrecognised origin", "something-else"},
	}

	for _, c := range cases {
		agent := &mockAgent{}
		startMockAgent(t, agent)
		rec := &mockRecoverd{}
		startMockRecoverd(t, rec)
		srv := newBootloaderServer(t)

		_, err := srv.setBootloaderUnlockArmed(true, testPIN, parseOrigin(c.origin), localPeer())
		if err == nil {
			t.Errorf("%s: arm succeeded, want refusal", c.name)
		}
		if agent.callCount() != 0 {
			t.Errorf("%s: recovery agent was contacted %d times, want 0", c.name, agent.callCount())
		}
		if rec.attempts() != 0 {
			t.Errorf("%s: recoverd was contacted %d times, want 0: a remote arm must be refused before the PIN is even considered",
				c.name, rec.attempts())
		}
	}
}

// A local caller with the correct PIN reaches the agent and arms it.
func TestArmUnlockLocalWithCorrectPIN(t *testing.T) {
	agent := &mockAgent{}
	startMockAgent(t, agent)
	startMockRecoverd(t, &mockRecoverd{})
	srv := newBootloaderServer(t)

	reply, err := srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, localPeer())
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !reply.OK {
		t.Errorf("reply.OK = false, want true")
	}
	if reply.Message != "consent updated" {
		t.Errorf("message = %q, want the agent's message", reply.Message)
	}
	armed, ok := agent.lastArmed()
	if !ok || !armed {
		t.Errorf("agent received armed = %v (present %v), want true", armed, ok)
	}
}

// Negative proof: every PIN that is not the right one refuses, and the
// privileged agent is never contacted. A wrong PIN that still reached the agent
// would mean the gate is decorative.
func TestArmUnlockRefusedForBadPIN(t *testing.T) {
	cases := []struct {
		name    string
		pin     string
		wantMsg string
		// verified is true when the attempt should reach recoverd at all.
		verified bool
	}{
		{name: "wrong pin", pin: "9999", wantMsg: msgPINWrong, verified: true},
		{name: "empty pin", pin: "", wantMsg: msgPINRequired},
		{name: "newline injection", pin: "1234\nverify\n0\n1234", wantMsg: msgPINRequired},
		{name: "carriage return injection", pin: "1234\r\n", wantMsg: msgPINRequired},
	}

	for _, c := range cases {
		agent := &mockAgent{}
		startMockAgent(t, agent)
		rec := &mockRecoverd{}
		startMockRecoverd(t, rec)
		srv := newBootloaderServer(t)

		reply, err := srv.setBootloaderUnlockArmed(true, c.pin, Origin{}, localPeer())
		if err == nil {
			t.Errorf("%s: arm succeeded, want refusal", c.name)
		}
		if reply.OK {
			t.Errorf("%s: reply.OK = true", c.name)
		}
		if reply.Message != c.wantMsg {
			t.Errorf("%s: message = %q, want %q", c.name, reply.Message, c.wantMsg)
		}
		if agent.callCount() != 0 {
			t.Errorf("%s: recovery agent contacted %d times, want 0", c.name, agent.callCount())
		}
		if !c.verified && rec.attempts() != 0 {
			t.Errorf("%s: recoverd contacted %d times, want 0 (malformed PIN must not burn an attempt)",
				c.name, rec.attempts())
		}
	}
}

// A malformed PIN must never be put on recoverd's newline delimited wire: the
// broker rejects it rather than letting it forge extra protocol lines.
func TestPINWellFormed(t *testing.T) {
	cases := []struct {
		pin  string
		want bool
	}{
		{"1234", true},
		{"a long passphrase with spaces", true},
		{"", false},
		{"12\n34", false},
		{"12\r34", false},
		{"verify\n0\n0000", false},
	}
	for _, c := range cases {
		if got := pinWellFormed(c.pin); got != c.want {
			t.Errorf("pinWellFormed(%q) = %v, want %v", c.pin, got, c.want)
		}
	}
}

// If recoverd cannot answer, arming fails closed: no agent call, no arming.
func TestArmUnlockFailsClosedWhenRecoverdUnreachable(t *testing.T) {
	agent := &mockAgent{}
	startMockAgent(t, agent)
	t.Setenv("USH_RECOVERD_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	srv := newBootloaderServer(t)

	reply, err := srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, localPeer())
	if err == nil {
		t.Error("arm succeeded with recoverd unreachable, want failure")
	}
	if reply.OK {
		t.Error("reply.OK = true with recoverd unreachable")
	}
	if reply.Message != msgPINUnavailable {
		t.Errorf("message = %q, want %q", reply.Message, msgPINUnavailable)
	}
	if agent.callCount() != 0 {
		t.Errorf("recovery agent contacted %d times, want 0", agent.callCount())
	}
}

// A recoverd that answers something other than OK is not an approval.
func TestArmUnlockRefusedOnUnexpectedRecoverdAnswer(t *testing.T) {
	answers := []string{"", "NO", "ERR rate limited", "ok", "OK EXTRA", "garbage"}

	for _, answer := range answers {
		agent := &mockAgent{}
		startMockAgent(t, agent)
		startMockRecoverd(t, &mockRecoverd{reply: answer, literal: true})
		srv := newBootloaderServer(t)

		if _, err := srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, localPeer()); err == nil {
			t.Errorf("answer %q: arm succeeded, want refusal", answer)
		}
		if agent.callCount() != 0 {
			t.Errorf("answer %q: agent contacted %d times, want 0", answer, agent.callCount())
		}
	}
}

// Disarming must never be blocked by the PIN gate: an owner who cannot produce a
// PIN must still be able to take consent away.
func TestDisarmNeedsNoPIN(t *testing.T) {
	agent := &mockAgent{}
	startMockAgent(t, agent)
	// No recoverd at all: disarming must not depend on it.
	t.Setenv("USH_RECOVERD_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	srv := newBootloaderServer(t)

	reply, err := srv.setBootloaderUnlockArmed(false, "", Origin{}, localPeer())
	if err != nil {
		t.Fatalf("disarm with empty PIN: %v", err)
	}
	if !reply.OK {
		t.Error("reply.OK = false, want true")
	}
	armed, ok := agent.lastArmed()
	if !ok || armed {
		t.Errorf("agent received armed = %v (present %v), want false", armed, ok)
	}
}

// The peer credentials are a real gate: an unknown peer, or one that is not the
// broker's user, is refused before the agent is contacted.
func TestArmUnlockRefusedForUnverifiedPeer(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	t.Setenv("USH_BROKER_CONFIRM", "yes")

	cases := []struct {
		name string
		peer peerIdentity
	}{
		{"credentials unreadable", peerIdentity{}},
		{"different uid", peerIdentity{known: true, uid: uint32(os.Getuid()) + 1}},
	}

	for _, c := range cases {
		agent := &mockAgent{}
		startMockAgent(t, agent)
		startMockRecoverd(t, &mockRecoverd{})
		srv := newBootloaderServer(t)

		if _, err := srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, c.peer); err == nil {
			t.Errorf("%s: arm succeeded, want refusal", c.name)
		}
		if agent.callCount() != 0 {
			t.Errorf("%s: agent contacted %d times, want 0", c.name, agent.callCount())
		}
	}
}

// Disarming is fail-safe, so a remote caller may do it, but it must genuinely
// reach the agent and must report a failure instead of swallowing it.
func TestDisarmIsAllowedRemotelyAndNotSilent(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	t.Setenv("USH_BROKER_CONFIRM", "no")

	agent := &mockAgent{}
	startMockAgent(t, agent)
	srv := newBootloaderServer(t)

	if _, err := srv.setBootloaderUnlockArmed(false, "", parseOrigin(SDBOrigin("workstation")), localPeer()); err != nil {
		t.Fatalf("remote disarm: %v", err)
	}
	armed, ok := agent.lastArmed()
	if !ok || armed {
		t.Errorf("agent received armed = %v (present %v), want false", armed, ok)
	}

	// The same disarm, refused by the agent, must surface as an error.
	failing := &mockAgent{body: `{"ok":false,"message":"state file is read only"}`}
	startMockAgent(t, failing)
	srv2 := newBootloaderServer(t)

	reply, err := srv2.setBootloaderUnlockArmed(false, "", Origin{}, localPeer())
	if err == nil {
		t.Error("agent refusal reported as success")
	}
	if !strings.Contains(err.Error(), "state file is read only") {
		t.Errorf("error = %v, want it to carry the agent message", err)
	}
	if reply.OK {
		t.Error("reply.OK = true after an agent refusal")
	}
}

// Every unexpected agent condition fails closed, for both methods.
func TestAgentFailuresFailClosed(t *testing.T) {
	cases := []struct {
		name        string
		unreachable bool
		status      int
		body        string
		wantErr     string
	}{
		{name: "unreachable socket", unreachable: true, wantErr: "unreachable"},
		{name: "internal error", status: http.StatusInternalServerError, wantErr: "status 500"},
		{name: "forbidden", status: http.StatusForbidden, wantErr: "status 403"},
		{name: "unparsable body", body: "not json at all", wantErr: "unparsable"},
		{name: "truncated body", body: `{"ok":tr`, wantErr: "unparsable"},
		{name: "html error page", body: "<html>gateway</html>", wantErr: "unparsable"},
	}

	for _, c := range cases {
		t.Setenv("USH_BROKER_AUTO", "allow_always")
		t.Setenv("USH_BROKER_CONFIRM", "yes")

		agent := &mockAgent{status: c.status, body: c.body}
		startMockRecoverd(t, &mockRecoverd{})
		if c.unreachable {
			// Point the broker at a path where nothing listens.
			t.Setenv("USH_ATOM_RECOVERY_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
		} else {
			startMockAgent(t, agent)
		}
		srv := newBootloaderServer(t)

		if _, err := srv.bootloaderLockState(); err == nil {
			t.Errorf("%s: lock state succeeded, want failure", c.name)
		} else if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: lock state error = %v, want it to mention %q", c.name, err, c.wantErr)
		}

		reply, err := srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, localPeer())
		if err == nil {
			t.Errorf("%s: arm succeeded, want failure", c.name)
		}
		if reply.OK {
			t.Errorf("%s: reply.OK = true on a failed call", c.name)
		}
	}
}

// The happy path for reading state, and the RPC shape the desktop is written
// against.
func TestLockStateRoundTripsThroughDispatch(t *testing.T) {
	agent := &mockAgent{lockBody: LockState{Locked: true, UnlockArmed: false, UnlockCount: 3}}
	startMockAgent(t, agent)
	srv := newBootloaderServer(t)

	resp := srv.dispatch(rpcRequest{Method: "BootloaderLockState"})
	if resp.Error != "" {
		t.Fatalf("dispatch error: %s", resp.Error)
	}
	if !resp.OK || !resp.Locked || resp.UnlockArmed || resp.UnlockCount != 3 {
		t.Errorf("resp = %+v, want ok/locked true, armed false, count 3", resp)
	}
}

// Through the wire path, an arm request carrying no peer credentials (which is
// what dispatch without a connection reports) is refused, and the response says
// so instead of coming back OK.
func TestArmThroughDispatchWithoutPeerIsRefused(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	t.Setenv("USH_BROKER_CONFIRM", "yes")

	agent := &mockAgent{}
	startMockAgent(t, agent)
	srv := newBootloaderServer(t)

	resp := srv.dispatch(rpcRequest{Method: "SetBootloaderUnlockArmed", Enable: true})
	if resp.Error == "" {
		t.Error("no error for an unverified peer")
	}
	if resp.OK {
		t.Error("resp.OK = true for an unverified peer")
	}
	if agent.callCount() != 0 {
		t.Errorf("agent contacted %d times, want 0", agent.callCount())
	}
}

// Regression: adding the bootloader methods and the peer plumbing left the
// existing dispatch behaviour alone, including the unknown-method answer.
func TestExistingDispatchUnchanged(t *testing.T) {
	srv := newBootloaderServer(t)

	if resp := srv.dispatch(rpcRequest{Method: "DevShellStatus"}); resp.Enabled {
		t.Error("DevShellStatus: Enabled = true on fresh storage")
	}
	if resp := srv.dispatch(rpcRequest{Method: "ListDevDirs"}); resp.Permissions != "null" && resp.Permissions != "[]" {
		t.Errorf("ListDevDirs = %q, want an empty list", resp.Permissions)
	}
	if resp := srv.dispatch(rpcRequest{Method: "IsAppTrusted", App: "/usr/bin/curl"}); resp.Trusted {
		t.Error("IsAppTrusted = true for an untrusted app")
	}
	resp := srv.dispatch(rpcRequest{Method: "NoSuchMethod"})
	if !strings.Contains(resp.Error, "unknown method") {
		t.Errorf("unknown method error = %q", resp.Error)
	}
}

// The management bus surface must be a thin wrapper over the same guarded
// internals, so the gates apply identically no matter which transport the
// desktop uses.
func TestDBusArmBootloaderUnlockReusesGuards(t *testing.T) {
	agent := &mockAgent{lockBody: LockState{Locked: true, UnlockCount: 2}}
	startMockAgent(t, agent)
	startMockRecoverd(t, &mockRecoverd{})
	mgr := &dbusManager{s: newBootloaderServer(t)}

	ok, msg, derr := mgr.ArmBootloaderUnlock(true, "9999")
	if derr != nil {
		t.Fatalf("unexpected D-Bus error: %v", derr)
	}
	if ok {
		t.Error("ok = true for a wrong PIN")
	}
	if msg != msgPINWrong {
		t.Errorf("message = %q, want %q", msg, msgPINWrong)
	}
	if agent.callCount() != 0 {
		t.Errorf("agent contacted %d times on a wrong PIN, want 0", agent.callCount())
	}

	ok, msg, derr = mgr.ArmBootloaderUnlock(true, testPIN)
	if derr != nil || !ok {
		t.Fatalf("correct PIN: ok = %v, err = %v", ok, derr)
	}
	if msg != "consent updated" {
		t.Errorf("message = %q, want the agent's message", msg)
	}

	// Disarm over D-Bus takes no PIN.
	if ok, _, derr := mgr.ArmBootloaderUnlock(false, ""); !ok || derr != nil {
		t.Errorf("disarm: ok = %v, err = %v", ok, derr)
	}

	locked, armed, count, derr := mgr.BootloaderLockState()
	if derr != nil {
		t.Fatalf("BootloaderLockState: %v", derr)
	}
	if !locked || armed || count != 2 {
		t.Errorf("state = (%v, %v, %d), want (true, false, 2)", locked, armed, count)
	}
}

// The broker must speak recoverd's protocol exactly: verify, the uid, the PIN.
func TestRecoverdRequestShape(t *testing.T) {
	startMockAgent(t, &mockAgent{})
	rec := &mockRecoverd{}
	startMockRecoverd(t, rec)
	srv := newBootloaderServer(t)

	if _, err := srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, localPeer()); err != nil {
		t.Fatalf("arm: %v", err)
	}

	got := rec.lastRequest()
	want := []string{"verify", strconv.Itoa(os.Getuid()), testPIN}
	if len(got) != len(want) {
		t.Fatalf("recoverd saw %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("recoverd line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The PIN must never reach the audit log, which is written to disk and read by
// support flows.
func TestPINNeverReachesAuditLog(t *testing.T) {
	startMockAgent(t, &mockAgent{})
	startMockRecoverd(t, &mockRecoverd{})

	dir := t.TempDir()
	srv, err := NewServer(dir)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	const secret = "8371-secret-pin"
	srv.setBootloaderUnlockArmed(true, secret, Origin{}, localPeer())
	srv.setBootloaderUnlockArmed(true, testPIN, Origin{}, localPeer())
	srv.auditLog.Close()

	entries, err := os.ReadDir(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, "audit", e.Name()))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if strings.Contains(string(data), secret) {
			t.Errorf("audit log %s contains the PIN", e.Name())
		}
	}
}
