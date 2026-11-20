// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"testing"
)

func trustServer(t *testing.T, answer string) (*Server, *int) {
	t.Helper()
	t.Setenv("USH_BROKER_AUTO", "")
	srv := newElevateServer(t)
	asked := 0
	srv.dialog = func(string, string, string) string {
		asked++
		return answer
	}
	return srv, &asked
}

func TestSdbAlwaysIsRememberedForThatHostAndAction(t *testing.T) {
	srv, asked := trustServer(t, "allow_always")
	origin := parseOrigin(SDBOrigin("workstation"))
	for _, path := range []string{"/etc/a", "/etc/b", "/usr/c"} {
		if ok, _ := srv.sdbElevate(sdbElevateWriteSystem, path, "KEY-A", origin); !ok {
			t.Fatalf("write to %s refused", path)
		}
	}
	if *asked != 1 {
		t.Fatalf("asked %d times, want 1", *asked)
	}
	reloaded, err := NewServer(srv.storageDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.sdbRemembered("KEY-A", sdbElevateWriteSystem); !ok {
		t.Fatal("always was not saved")
	}
}

func TestSdbRememberedGrantDoesNotCrossHostsOrActions(t *testing.T) {
	srv, asked := trustServer(t, "allow_always")
	origin := parseOrigin(SDBOrigin("workstation"))
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", origin)
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-B", origin)
	srv.sdbElevate(sdbElevateBindPrivilegedPort, "80", "KEY-A", origin)
	if *asked != 3 {
		t.Fatalf("asked %d times, want 3", *asked)
	}
}

func TestSdbSessionGrantIsNotSaved(t *testing.T) {
	srv, asked := trustServer(t, "allow_session")
	origin := parseOrigin(SDBOrigin("workstation"))
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", origin)
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/b", "KEY-A", origin)
	if *asked != 1 {
		t.Fatalf("asked %d times, want 1", *asked)
	}
	reloaded, err := NewServer(srv.storageDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.sdbRemembered("KEY-A", sdbElevateWriteSystem); ok {
		t.Fatal("a session grant survived the broker")
	}
}

func TestSdbOnceIsAskedAgain(t *testing.T) {
	srv, asked := trustServer(t, "allow")
	origin := parseOrigin(SDBOrigin("workstation"))
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", origin)
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", origin)
	if *asked != 2 {
		t.Fatalf("asked %d times, want 2", *asked)
	}
}

func TestSdbAutoApproveSkipsTheDialog(t *testing.T) {
	srv, asked := trustServer(t, "deny")
	if err := srv.setSdbAutoApprove(true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", parseOrigin(SDBOrigin("ws"))); !ok {
		t.Fatal("auto-approve did not grant")
	}
	if *asked != 0 {
		t.Fatalf("asked %d times, want 0", *asked)
	}
	if err := srv.setSdbAutoApprove(false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", parseOrigin(SDBOrigin("ws"))); ok {
		t.Fatal("granted after auto-approve was turned off and the dialog denied")
	}
}

func TestSdbAutoApproveCannotOpenRootOnALockedDevice(t *testing.T) {
	srv, _ := trustServer(t, "allow_always")
	agent := &mockAgent{lockBody: LockState{Locked: true}}
	startMockAgent(t, agent)
	if err := srv.setSdbAutoApprove(true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := srv.sdbElevate(sdbElevateShellRoot, "", "KEY-A", parseOrigin(SDBOrigin("ws"))); ok {
		t.Fatal("root shell granted on a locked device")
	}
}

func TestSdbResetForgetsRememberedGrantsButKeepsTheSwitch(t *testing.T) {
	srv, asked := trustServer(t, "allow_always")
	origin := parseOrigin(SDBOrigin("workstation"))
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", origin)
	if err := srv.resetSdbApprovals(); err != nil {
		t.Fatal(err)
	}
	srv.sdbElevate(sdbElevateWriteSystem, "/etc/a", "KEY-A", origin)
	if *asked != 2 {
		t.Fatalf("asked %d times, want 2", *asked)
	}
}
