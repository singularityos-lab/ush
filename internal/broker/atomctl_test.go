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
	// managerFails makes status and list-units reply OK=false.
	managerFails bool
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
				fail, managerFails := f.fail, f.managerFails
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
				case "status", "sdb-status":
					if managerFails {
						atomWriteFrame(c, atomReply{Error: "manager unavailable"})
						return
					}
					state := "unknown"
					unitName := req.Unit
					if req.Cmd == "sdb-status" {
						unitName = "sdbd.service"
					}
					for _, unit := range units {
						if unit.Name == unitName {
							state = unit.State
							break
						}
					}
					atomWriteFrame(c, atomReply{OK: true, State: state})
				case "list-units":
					if managerFails {
						atomWriteFrame(c, atomReply{Error: "manager unavailable"})
						return
					}
					atomWriteFrame(c, atomReply{OK: true, Units: units})
				case "start", "stop", "sdb-enable", "sdb-disable":
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
	t.Setenv("USH_ATOM_SDB_CONTROL_SOCK", sock)
}

// Present is true only when the init knows the unit file.
func TestAtomServicePresent(t *testing.T) {
	cases := []struct {
		name         string
		units        []atomUnitStatus
		managerFails bool
		want         bool
		wantErr      bool
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
		{name: "status refused", managerFails: true, wantErr: true},
	}

	for _, c := range cases {
		f := &fakeInit{units: c.units, managerFails: c.managerFails}
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
	if got[0].Cmd != "sdb-enable" || got[0].Unit != "" {
		t.Errorf("first request = %+v, want sdb-enable", got[0])
	}
	if got[1].Cmd != "sdb-disable" || got[1].Unit != "" {
		t.Errorf("second request = %+v, want sdb-disable", got[1])
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
		// breaksPresent is false for a transport that answers status and only
		// refuses mutation. Present is then legitimately (false, nil).
		breaksPresent bool
	}{
		{name: "socket unreachable", unreachable: true, breaksPresent: true},
		{name: "permission denied", fail: "permission denied"},
		{name: "unknown unit", fail: "unknown unit"},
		{name: "unparsable reply", garbage: true, breaksPresent: true},
		{name: "connection closed", hangup: true, breaksPresent: true},
	}

	for _, c := range cases {
		f := &fakeInit{fail: c.fail, garbage: c.garbage, hangup: c.hangup}
		if c.unreachable {
			t.Setenv("USH_ATOM_CONTROL_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
			t.Setenv("USH_ATOM_SDB_CONTROL_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
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

// End to end over the real framing: the broker's status and switch paths on top
// of a fake init, with the observation still coming from the socket probe.
func TestSdbOverInitControl(t *testing.T) {
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
