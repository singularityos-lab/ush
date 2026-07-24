// SPDX-License-Identifier: GPL-3.0-or-later

package broker

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeInit speaks the init's real wire format: a 4-byte big-endian length prefix
// followed by JSON. Testing against the actual framing is the point; a mock that
// spoke newline JSON would prove nothing about talking to PID 1.
type fakeInit struct {
	mu    sync.Mutex
	calls []atomRequest

	units []atomUnitStatus
	// fail makes every mutation reply with OK=false and this error.
	fail string
	// listFails makes list-units reply OK=false.
	listFails bool
	// garbage makes the server answer with a frame that is not a valid reply.
	garbage bool
	// hangup makes the server close without answering.
	hangup bool
	// observe runs as each request arrives, before any reply is sent.
	observe func(atomRequest)
}

func (f *fakeInit) requests() []atomRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]atomRequest(nil), f.calls...)
}

func startFakeInit(t *testing.T, f *fakeInit) {
	t.Helper()

	dir, err := os.MkdirTemp("", "ush-init")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	sock := filepath.Join(dir, "c.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req atomRequest
				if err := atomReadFrame(c, &req); err != nil {
					return
				}
				f.mu.Lock()
				f.calls = append(f.calls, req)
				observe := f.observe
				fail, listFails := f.fail, f.listFails
				garbage, hangup := f.garbage, f.hangup
				units := f.units
				f.mu.Unlock()

				if observe != nil {
					observe(req)
				}
				if hangup {
					return
				}
				if garbage {
					c.Write([]byte{0, 0, 0, 4})
					c.Write([]byte("nope"))
					return
				}
				switch req.Cmd {
				case "list-units":
					if listFails {
						atomWriteFrame(c, atomReply{Error: "manager unavailable"})
						return
					}
					atomWriteFrame(c, atomReply{OK: true, Units: units})
				case "start", "stop":
					if fail != "" {
						atomWriteFrame(c, atomReply{Error: fail})
						return
					}
					atomWriteFrame(c, atomReply{OK: true, State: req.Cmd})
				default:
					atomWriteFrame(c, atomReply{Error: "unknown command: " + req.Cmd})
				}
			}(conn)
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		os.RemoveAll(dir)
	})

	t.Setenv("USH_ATOM_CONTROL_SOCK", sock)
}

// Present is true only when the init actually lists the unit.
func TestAtomServicePresent(t *testing.T) {
	cases := []struct {
		name      string
		units     []atomUnitStatus
		listFails bool
		want      bool
		wantErr   bool
	}{
		{
			name:  "unit listed",
			units: []atomUnitStatus{{Name: "other"}, {Name: "sdbd.service", State: "running"}},
			want:  true,
		},
		{
			name:  "unit absent",
			units: []atomUnitStatus{{Name: "other"}},
			want:  false,
		},
		{name: "no units at all", want: false},
		{name: "list refused", listFails: true, wantErr: true},
	}

	for _, c := range cases {
		f := &fakeInit{units: c.units, listFails: c.listFails}
		startFakeInit(t, f)

		got, err := (atomSdbService{}).Present()
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: err = nil, want an error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: Present = %v, want %v", c.name, got, c.want)
		}
	}
}

// The broker must issue start and stop, and must NOT attempt enable or disable:
// under this init they do not exist as live operations and the image is read
// only, so a request for them could only ever be a lie.
func TestAtomServiceIssuesOnlyStartAndStop(t *testing.T) {
	markerFixture(t)
	f := &fakeInit{}
	startFakeInit(t, f)

	if err := (atomSdbService{}).SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if err := (atomSdbService{}).SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}

	got := f.requests()
	if len(got) != 2 {
		t.Fatalf("requests = %d, want 2", len(got))
	}
	if got[0].Cmd != "start" || got[0].Unit != "sdbd.service" {
		t.Errorf("first request = %+v, want start of sinty-sdb", got[0])
	}
	if got[1].Cmd != "stop" || got[1].Unit != "sdbd.service" {
		t.Errorf("second request = %+v, want stop of sinty-sdb", got[1])
	}
	for _, r := range got {
		if r.Cmd == "enable" || r.Cmd == "disable" {
			t.Errorf("broker issued %q, which does not exist on this init", r.Cmd)
		}
	}
}

// Every way the init can fail to carry out the command is an error, never a
// quiet success.
func TestAtomServiceFailsClosed(t *testing.T) {
	cases := []struct {
		name        string
		unreachable bool
		fail        string
		garbage     bool
		hangup      bool
		// breaksPresent is false for a transport that answers list-units fine and
		// only refuses the mutation: Present is then legitimately (false, nil),
		// meaning "unit not listed", which is not an error.
		breaksPresent bool
	}{
		{name: "socket unreachable", unreachable: true, breaksPresent: true},
		{name: "permission denied", fail: "permission denied"},
		{name: "unknown unit", fail: "unknown unit"},
		{name: "unparsable reply", garbage: true, breaksPresent: true},
		{name: "connection closed", hangup: true, breaksPresent: true},
	}

	for _, c := range cases {
		markerFixture(t)
		f := &fakeInit{fail: c.fail, garbage: c.garbage, hangup: c.hangup}
		if c.unreachable {
			t.Setenv("USH_ATOM_CONTROL_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
		} else {
			startFakeInit(t, f)
		}

		if err := (atomSdbService{}).SetEnabled(true); err == nil {
			t.Errorf("%s: SetEnabled = nil, want an error", c.name)
		}
		present, err := (atomSdbService{}).Present()
		if c.breaksPresent {
			if err == nil {
				t.Errorf("%s: Present err = nil, want an error", c.name)
			}
			continue
		}
		if present {
			t.Errorf("%s: Present = true, want false", c.name)
		}
	}
}

// The unit name is configurable because the image ships the unit, not this repo.
func TestAtomServiceHonoursUnitOverride(t *testing.T) {
	markerFixture(t)
	f := &fakeInit{units: []atomUnitStatus{{Name: "custom-bridge"}}}
	startFakeInit(t, f)
	t.Setenv("USH_SDB_UNIT", "custom-bridge")

	present, err := (atomSdbService{}).Present()
	if err != nil || !present {
		t.Fatalf("Present = %v, %v, want true, nil", present, err)
	}
	if err := (atomSdbService{}).SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	got := f.requests()
	if got[len(got)-1].Unit != "custom-bridge" {
		t.Errorf("unit = %q, want custom-bridge", got[len(got)-1].Unit)
	}
}

// End to end over the real framing: the broker's status and switch paths on top
// of a fake init, with the observation still coming from the socket probe.
func TestSdbOverInitControl(t *testing.T) {
	markerFixture(t)
	f := &fakeInit{units: []atomUnitStatus{{Name: "sdbd.service", State: "stopped"}}}
	startFakeInit(t, f)

	srv, svc, sock := newSdbFixture(t, false)
	// Use the real init-backed control rather than the fake service.
	sdbControl = atomSdbService{}
	_ = svc

	available, active, msg := srv.sdbStatus()
	if !available || active || msg != msgSdbOff {
		t.Errorf("status = (%v, %v, %q), want (true, false, %q)", available, active, msg, msgSdbOff)
	}

	// The init reports success but nothing starts listening, which is exactly the
	// case the observation exists to catch.
	ok, active, msg := srv.setSdbEnabled(true, Origin{}, localPeer())
	if ok {
		t.Error("ok = true although nothing is listening")
	}
	if active {
		t.Error("active = true although nothing is listening")
	}
	if msg != msgSdbStartFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStartFailed)
	}

	// With the listener genuinely up, the same call succeeds.
	sock.start()
	ok, active, msg = srv.setSdbEnabled(true, Origin{}, localPeer())
	if !ok || !active || msg != msgSdbOn {
		t.Errorf("switch = (%v, %v, %q), want (true, true, %q)", ok, active, msg, msgSdbOn)
	}
}

// markerFixture points the opt-in marker at a temp path and returns it.
func markerFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sinty-sdb", "enabled")
	t.Setenv("USH_SDB_OPT_IN", path)
	return path
}

func markerExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err == nil
}

// The marker is created on enable and removed on disable, and it is the marker
// that carries the choice across a reboot.
func TestOptInMarkerFollowsTheSwitch(t *testing.T) {
	marker := markerFixture(t)
	f := &fakeInit{}
	startFakeInit(t, f)

	if markerExists(t, marker) {
		t.Fatal("marker present before anything was enabled")
	}
	if err := (atomSdbService{}).SetEnabled(true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !markerExists(t, marker) {
		t.Error("marker absent after enable")
	}
	if err := (atomSdbService{}).SetEnabled(false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if markerExists(t, marker) {
		t.Error("marker still present after disable")
	}

	// Turning off an already-off bridge is not an error.
	if err := (atomSdbService{}).SetEnabled(false); err != nil {
		t.Errorf("second disable: %v", err)
	}
}

// The ordering is the safety property: the marker must move BEFORE the init
// command, in both directions, so an interruption leaves the closed state.
func TestOptInMarkerMovesBeforeTheInitCommand(t *testing.T) {
	marker := markerFixture(t)

	cases := []struct {
		name       string
		enable     bool
		wantCmd    string
		wantMarker bool
	}{
		{name: "enable creates before start", enable: true, wantCmd: "start", wantMarker: true},
		{name: "disable removes before stop", enable: false, wantCmd: "stop", wantMarker: false},
	}

	for _, c := range cases {
		// Observe the marker state at the moment the init command arrives.
		var seen bool
		f := &fakeInit{observe: func(req atomRequest) {
			if req.Cmd == c.wantCmd {
				seen = markerExists(t, marker)
			}
		}}
		startFakeInit(t, f)

		if c.enable {
			os.Remove(marker)
		} else {
			os.MkdirAll(filepath.Dir(marker), 0o755)
			os.WriteFile(marker, nil, 0o644)
		}

		if err := (atomSdbService{}).SetEnabled(c.enable); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if seen != c.wantMarker {
			t.Errorf("%s: marker was %v when %s reached the init, want %v",
				c.name, seen, c.wantCmd, c.wantMarker)
		}
	}
}

// Negative proof: a marker that cannot be written is a hard failure, and no init
// command is sent. Changing the live state while the persistent state stayed
// behind is the disagreement the ordering exists to prevent.
func TestOptInMarkerFailureBlocksTheInitCommand(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, an unwritable directory cannot be simulated")
	}

	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Setenv("USH_SDB_OPT_IN", filepath.Join(locked, "enabled"))

	f := &fakeInit{}
	startFakeInit(t, f)

	if err := (atomSdbService{}).SetEnabled(true); err == nil {
		t.Error("enable succeeded with an unwritable marker directory")
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("init received %d commands, want 0: the live state must not move when the marker cannot", len(got))
	}
}

// The broker-level view of the same failure: ok=false, never an optimistic
// success, and the observed state is reported rather than the requested one.
func TestSdbEnableFailsClosedWhenMarkerUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, an unwritable directory cannot be simulated")
	}

	f := &fakeInit{units: []atomUnitStatus{{Name: "sdbd.service"}}}
	startFakeInit(t, f)

	srv, _, _ := newSdbFixture(t, false)
	sdbControl = atomSdbService{}

	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Setenv("USH_SDB_OPT_IN", filepath.Join(locked, "enabled"))

	ok, active, msg := srv.setSdbEnabled(true, Origin{}, localPeer())
	if ok {
		t.Error("ok = true although the marker could not be written")
	}
	if active {
		t.Error("active = true although nothing started")
	}
	if msg != msgSdbStartFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStartFailed)
	}
}

// Negative proof: an enable whose start does not take still leaves the marker
// present (the owner did ask for the bridge), but reports active=false.
func TestEnableWithFailedStartKeepsMarkerAndReportsInactive(t *testing.T) {
	marker := markerFixture(t)
	f := &fakeInit{units: []atomUnitStatus{{Name: "sdbd.service"}}}
	startFakeInit(t, f)

	srv, _, _ := newSdbFixture(t, false)
	sdbControl = atomSdbService{}

	ok, active, msg := srv.setSdbEnabled(true, Origin{}, localPeer())
	if ok {
		t.Error("ok = true although nothing is listening")
	}
	if active {
		t.Error("active = true although nothing is listening")
	}
	if msg != msgSdbStartFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStartFailed)
	}
	if !markerExists(t, marker) {
		t.Error("marker absent after an enable whose start failed")
	}
}

// Negative proof: a disable whose stop fails still removes the marker, so the
// bridge cannot come back at next boot, and reports ok=false with active=true so
// the desktop keeps the switch on for a listener that is still accepting.
func TestDisableWithFailedStopStillRemovesMarker(t *testing.T) {
	marker := markerFixture(t)
	os.MkdirAll(filepath.Dir(marker), 0o755)
	os.WriteFile(marker, nil, 0o644)

	f := &fakeInit{units: []atomUnitStatus{{Name: "sdbd.service"}}, fail: "permission denied"}
	startFakeInit(t, f)

	srv, _, _ := newSdbFixture(t, true)
	sdbControl = atomSdbService{}

	ok, active, msg := srv.setSdbEnabled(false, Origin{}, localPeer())
	if ok {
		t.Error("ok = true although the stop failed")
	}
	if !active {
		t.Error("active = false although the listener is still accepting connections")
	}
	if msg != msgSdbStopFailed {
		t.Errorf("message = %q, want %q", msg, msgSdbStopFailed)
	}
	if markerExists(t, marker) {
		t.Error("marker still present after a disable: the bridge would return at next boot")
	}
}
