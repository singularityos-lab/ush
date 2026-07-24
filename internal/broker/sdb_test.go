// SPDX-License-Identifier: GPL-3.0-or-later

package broker

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeSdbService stands in for the init system. It records what it was asked to
// do and, crucially, can be told to LIE: to report success while leaving the
// listener exactly as it was. That is the case the observed-state rule exists to
// catch, and it cannot be tested with a service that always tells the truth.
type fakeSdbService struct {
	mu sync.Mutex

	present    bool
	presentErr error

	setErr error
	// silent makes SetEnabled report success without changing the socket.
	silent bool

	calls []bool

	sock *fakeSdbd
}

func (f *fakeSdbService) Present() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present, f.presentErr
}

func (f *fakeSdbService) SetEnabled(on bool) error {
	f.mu.Lock()
	f.calls = append(f.calls, on)
	silent, err, sock := f.silent, f.setErr, f.sock
	f.mu.Unlock()

	if !silent && sock != nil {
		if on {
			sock.start()
		} else {
			sock.stop()
		}
	}
	return err
}

func (f *fakeSdbService) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeSdbd is a listening socket standing in for a serving sdbd.
type fakeSdbd struct {
	mu   sync.Mutex
	path string
	ln   net.Listener
}

func (f *fakeSdbd) start() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		return
	}
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		return
	}
	f.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}

func (f *fakeSdbd) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln == nil {
		return
	}
	f.ln.Close()
	f.ln = nil
	os.Remove(f.path)
}

// newSdbFixture wires a fake service and a fake sdbd socket into the broker for
// the duration of one test.
func newSdbFixture(t *testing.T, serving bool) (*Server, *fakeSdbService, *fakeSdbd) {
	t.Helper()

	// The settle window only matters on paths that never reach the requested
	// state; shorten it so those tests do not each wait the production timeout.
	prevTimeout, prevPoll := sdbSettleTimeout, sdbSettlePoll
	sdbSettleTimeout, sdbSettlePoll = 150*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { sdbSettleTimeout, sdbSettlePoll = prevTimeout, prevPoll })

	dir, err := os.MkdirTemp("", "ush-sdb")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	sock := &fakeSdbd{path: filepath.Join(dir, "s.sock")}
	if serving {
		sock.start()
	}
	t.Cleanup(func() {
		sock.stop()
		os.RemoveAll(dir)
	})

	t.Setenv("USH_SDB_SOCK", sock.path)

	// Dev unlocked by default; individual tests point the gate elsewhere.
	gate := filepath.Join(dir, "dev.enabled")
	if err := os.WriteFile(gate, nil, 0644); err != nil {
		t.Fatalf("write gate: %v", err)
	}
	t.Setenv("USH_DEV_GATE", gate)

	svc := &fakeSdbService{present: true, sock: sock}
	prev := sdbControl
	sdbControl = svc
	t.Cleanup(func() { sdbControl = prev })

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Stop)

	return srv, svc, sock
}

// With the init unreachable the broker cannot determine or change anything, so
// it reports unavailable rather than pretending it can switch a service. The
// control socket is pointed at an absent path explicitly: falling through to the
// real one would make this test depend on whether the host runs the init.
func TestSdbReportsUnavailableWhenInitUnreachable(t *testing.T) {
	t.Setenv("USH_SDB_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	t.Setenv("USH_ATOM_CONTROL_SOCK", filepath.Join(t.TempDir(), "no-init.sock"))
	t.Setenv("USH_SDB_OPT_IN", filepath.Join(t.TempDir(), "sinty-sdb", "enabled"))

	prev := sdbControl
	sdbControl = atomSdbService{}
	t.Cleanup(func() { sdbControl = prev })

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	available, active, msg := srv.sdbStatus()
	if available {
		t.Error("available = true with no service control configured")
	}
	if active {
		t.Error("active = true with no service control configured")
	}
	if msg != msgSdbNotControlled {
		t.Errorf("message = %q, want %q", msg, msgSdbNotControlled)
	}

	ok, active, _ := srv.setSdbEnabled(true, Origin{}, localPeer())
	if ok || active {
		t.Errorf("enable: ok = %v, active = %v, want false/false", ok, active)
	}
}

// Availability is false when the unit is absent or dev is not unlocked, which is
// what greys the control out in the desktop.
func TestSdbAvailability(t *testing.T) {
	cases := []struct {
		name          string
		present       bool
		presentErr    error
		devUnlocked   bool
		serving       bool
		wantAvailable bool
		wantMessage   string
	}{
		{name: "installed and unlocked", present: true, devUnlocked: true, wantAvailable: true, wantMessage: msgSdbOff},
		{name: "serving", present: true, devUnlocked: true, serving: true, wantAvailable: true, wantMessage: msgSdbOn},
		{name: "unit absent", present: false, devUnlocked: true, wantMessage: msgSdbNotInstalled},
		{name: "dev locked", present: true, devUnlocked: false, wantMessage: msgSdbDevLocked},
		{name: "both missing", present: false, devUnlocked: false, wantMessage: msgSdbNotInstalled},
	}

	for _, c := range cases {
		srv, svc, _ := newSdbFixture(t, c.serving)
		svc.present = c.present
		svc.presentErr = c.presentErr
		if !c.devUnlocked {
			t.Setenv("USH_DEV_GATE", filepath.Join(t.TempDir(), "no-gate"))
		}

		available, active, msg := srv.sdbStatus()
		if available != c.wantAvailable {
			t.Errorf("%s: available = %v, want %v", c.name, available, c.wantAvailable)
		}
		if msg != c.wantMessage {
			t.Errorf("%s: message = %q, want %q", c.name, msg, c.wantMessage)
		}
		if active != c.serving {
			t.Errorf("%s: active = %v, want %v", c.name, active, c.serving)
		}
	}
}

// Negative proof: enabling when the bridge is unavailable is refused, and the
// reported state is not "active".
func TestSdbEnableRefusedWhenUnavailable(t *testing.T) {
	cases := []struct {
		name        string
		present     bool
		devUnlocked bool
		wantMessage string
	}{
		{name: "unit absent", present: false, devUnlocked: true, wantMessage: msgSdbNotInstalled},
		{name: "dev locked", present: true, devUnlocked: false, wantMessage: msgSdbDevLocked},
	}

	for _, c := range cases {
		srv, svc, _ := newSdbFixture(t, false)
		svc.present = c.present
		if !c.devUnlocked {
			t.Setenv("USH_DEV_GATE", filepath.Join(t.TempDir(), "no-gate"))
		}

		ok, active, msg := srv.setSdbEnabled(true, Origin{}, localPeer())
		if ok {
			t.Errorf("%s: ok = true, want false", c.name)
		}
		if active {
			t.Errorf("%s: active = true, want false", c.name)
		}
		if msg != c.wantMessage {
			t.Errorf("%s: message = %q, want %q", c.name, msg, c.wantMessage)
		}
		if svc.callCount() != 0 {
			t.Errorf("%s: service was switched %d times, want 0", c.name, svc.callCount())
		}
	}
}

// Negative proof: a disable that does not actually stop the listener reports
// ok=false AND active=true, so the desktop keeps the switch on. Reporting the
// requested state here would tell the user the bridge is closed while it is
// still accepting connections.
func TestSdbFailedDisableReportsStillActive(t *testing.T) {
	srv, svc, _ := newSdbFixture(t, true)
	svc.silent = true

	ok, active, msg := srv.setSdbEnabled(false, Origin{}, localPeer())
	if ok {
		t.Error("ok = true for a disable that did not stop the service")
	}
	if !active {
		t.Error("active = false while the listener is still accepting connections")
	}
	if msg != msgSdbStopFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStopFailed)
	}
}

// The same in the other direction: an enable that does not bring the listener up
// must not be reported as active.
func TestSdbFailedEnableReportsNotActive(t *testing.T) {
	srv, svc, _ := newSdbFixture(t, false)
	svc.silent = true

	ok, active, msg := srv.setSdbEnabled(true, Origin{}, localPeer())
	if ok {
		t.Error("ok = true for an enable that did not start the service")
	}
	if active {
		t.Error("active = true while nothing is listening")
	}
	if msg != msgSdbStartFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStartFailed)
	}
}

// A service command that fails outright is still reported from observation.
func TestSdbSwitchErrorReportsObservedState(t *testing.T) {
	srv, svc, _ := newSdbFixture(t, true)
	svc.silent = true
	svc.setErr = errSdbServiceUnconfigured

	ok, active, _ := srv.setSdbEnabled(false, Origin{}, localPeer())
	if ok {
		t.Error("ok = true after a failed stop")
	}
	if !active {
		t.Error("active = false after a stop that failed, want true")
	}
}

// The happy paths, where observation confirms the request.
func TestSdbSwitchSucceeds(t *testing.T) {
	srv, _, sock := newSdbFixture(t, false)

	ok, active, msg := srv.setSdbEnabled(true, Origin{}, localPeer())
	if !ok || !active {
		t.Fatalf("enable: ok = %v, active = %v, want true/true", ok, active)
	}
	if msg != msgSdbOn {
		t.Errorf("enable message = %q, want %q", msg, msgSdbOn)
	}

	ok, active, msg = srv.setSdbEnabled(false, Origin{}, localPeer())
	if !ok || active {
		t.Fatalf("disable: ok = %v, active = %v, want true/false", ok, active)
	}
	if msg != msgSdbOff {
		t.Errorf("disable message = %q, want %q", msg, msgSdbOff)
	}
	sock.stop()
}

// Negative proof: a remote caller can switch the bridge in neither direction,
// and the service is never touched.
func TestSdbRemoteOriginCannotSwitch(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		enabled bool
	}{
		{"remote enable", SDBOrigin("workstation"), true},
		{"remote disable", SDBOrigin("workstation"), false},
		{"unlabelled bridge enable", SDBOrigin(""), true},
		{"unknown origin disable", "something-else", false},
	}

	for _, c := range cases {
		srv, svc, _ := newSdbFixture(t, true)

		ok, active, msg := srv.setSdbEnabled(c.enabled, parseOrigin(c.origin), localPeer())
		if ok {
			t.Errorf("%s: ok = true, want false", c.name)
		}
		if msg != msgSdbRemoteRefused {
			t.Errorf("%s: message = %q, want %q", c.name, msg, msgSdbRemoteRefused)
		}
		// The bridge was serving and must still be reported as serving.
		if !active {
			t.Errorf("%s: active = false, want the observed true", c.name)
		}
		if svc.callCount() != 0 {
			t.Errorf("%s: service switched %d times, want 0", c.name, svc.callCount())
		}
	}
}

// An unverified peer cannot switch the bridge either.
func TestSdbUnverifiedPeerCannotSwitch(t *testing.T) {
	cases := []struct {
		name string
		peer peerIdentity
	}{
		{"credentials unreadable", peerIdentity{}},
		{"different uid", peerIdentity{known: true, uid: uint32(os.Getuid()) + 1}},
	}

	for _, c := range cases {
		srv, svc, _ := newSdbFixture(t, true)

		ok, _, msg := srv.setSdbEnabled(false, Origin{}, c.peer)
		if ok {
			t.Errorf("%s: ok = true, want false", c.name)
		}
		if msg != msgPeerUnverified {
			t.Errorf("%s: message = %q, want %q", c.name, msg, msgPeerUnverified)
		}
		if svc.callCount() != 0 {
			t.Errorf("%s: service switched %d times, want 0", c.name, svc.callCount())
		}
	}
}

// Disabling must never be blocked by the development gate: a device whose gate
// was removed while the bridge is up still needs the switch that closes it.
func TestSdbDisableNotBlockedByDevGate(t *testing.T) {
	srv, svc, _ := newSdbFixture(t, true)
	t.Setenv("USH_DEV_GATE", filepath.Join(t.TempDir(), "no-gate"))

	ok, active, _ := srv.setSdbEnabled(false, Origin{}, localPeer())
	if !ok {
		t.Error("disable refused because dev is locked, want it allowed")
	}
	if active {
		t.Error("active = true after a successful disable")
	}
	if svc.callCount() != 1 {
		t.Errorf("service switched %d times, want 1", svc.callCount())
	}
}

// pessimisticActive must never return the reassuring answer.
func TestPessimisticActive(t *testing.T) {
	if pessimisticActive(true) {
		t.Error("pessimisticActive(enable) = true, want false: an unknown start must not look running")
	}
	if !pessimisticActive(false) {
		t.Error("pessimisticActive(disable) = false, want true: an unknown stop must not look closed")
	}
}

// activeOrUnknown must never report active on an unusable probe.
func TestActiveOrUnknown(t *testing.T) {
	cases := []struct {
		active, known, want bool
	}{
		{true, true, true},
		{false, true, false},
		{true, false, false},
		{false, false, false},
	}
	for _, c := range cases {
		if got := activeOrUnknown(c.active, c.known); got != c.want {
			t.Errorf("activeOrUnknown(%v, %v) = %v, want %v", c.active, c.known, got, c.want)
		}
	}
}

// The management bus surface is a thin wrapper over the same internals.
func TestDBusSdbMethodsReuseGuards(t *testing.T) {
	srv, svc, _ := newSdbFixture(t, false)
	mgr := &dbusManager{s: srv}

	available, active, msg, derr := mgr.SdbStatus()
	if derr != nil {
		t.Fatalf("SdbStatus: %v", derr)
	}
	if !available || active || msg != msgSdbOff {
		t.Errorf("SdbStatus = (%v, %v, %q), want (true, false, %q)", available, active, msg, msgSdbOff)
	}

	ok, active, _, derr2 := mgr.SetSdbEnabled(true)
	if derr2 != nil {
		t.Fatalf("SetSdbEnabled: %v", derr2)
	}
	if !ok || !active {
		t.Errorf("SetSdbEnabled(true) = (%v, %v), want (true, true)", ok, active)
	}

	// A silent service must surface through D-Bus as a failed stop that is still
	// active, exactly as it does on the internal path.
	svc.silent = true
	ok, active, msg, _ = mgr.SetSdbEnabled(false)
	if ok {
		t.Error("SetSdbEnabled(false) ok = true for a stop that did nothing")
	}
	if !active {
		t.Error("SetSdbEnabled(false) active = false while still listening")
	}
	if msg != msgSdbStopFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStopFailed)
	}
}
