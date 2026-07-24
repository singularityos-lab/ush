// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"path/filepath"
	"strings"
	"testing"
)

// A bridge elevation must NEVER be granted without a person at the device, even
// under the most permissive scripted policy. USH_BROKER_AUTO=allow_always is the
// widest possible default, yet a remote request has no user to approve it, so
// every action denies. If any of these ever returns granted, the bridge has a
// path to root that skips the human, which is the whole thing this guards.
func TestSdbElevateFailsClosedWithNoUser(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	srv := newElevateServer(t)

	cases := []struct {
		name           string
		action, detail string
	}{
		{"root shell", sdbElevateShellRoot, ""},
		{"system write", sdbElevateWriteSystem, "/etc/passwd"},
		{"privileged port", sdbElevateBindPrivilegedPort, "80"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			granted, reason := srv.sdbElevate(c.action, c.detail, "sess-1", parseOrigin(SDBOrigin("workstation")))
			if granted {
				t.Fatalf("%s granted with no user present, want denied", c.action)
			}
			if reason == "granted" {
				t.Fatalf("%s reason=%q, want a denial reason", c.action, reason)
			}
		})
	}
}

// An unrecognised action is refused outright, before any prompt could be shown.
// This keeps a future or malformed action from falling through into the approval
// path where a distracted user might wave it through.
func TestSdbElevateUnknownActionRefused(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "deny") // even a would-be prompt is irrelevant
	srv := newElevateServer(t)

	granted, reason := srv.sdbElevate("frobnicate", "whatever", "sess-1", parseOrigin(SDBOrigin("ws")))
	if granted {
		t.Fatal("unknown action granted, want refused")
	}
	if reason != "unknown elevation action" {
		t.Fatalf("reason=%q, want %q", reason, "unknown elevation action")
	}
}

// A privileged action that needs an argument (a path to write, a port to bind)
// is refused when the argument is missing, rather than mediating an empty target.
func TestSdbElevateMissingArgumentRefused(t *testing.T) {
	srv := newElevateServer(t)

	cases := []struct {
		action, wantReason string
	}{
		{sdbElevateWriteSystem, "write-system requires a target path"},
		{sdbElevateBindPrivilegedPort, "bind-privileged-port requires a port"},
	}
	for _, c := range cases {
		granted, reason := srv.sdbElevate(c.action, "   ", "sess-1", parseOrigin(SDBOrigin("ws")))
		if granted {
			t.Fatalf("%s with empty detail granted, want refused", c.action)
		}
		if reason != c.wantReason {
			t.Fatalf("%s reason=%q, want %q", c.action, reason, c.wantReason)
		}
	}
}

// The dialog resource carries the already-confined path verbatim so the person
// approving sees exactly which system path a remote host wants to write. The
// broker mediates the privilege on that path; it does not re-derive or widen it.
func TestSdbElevateDescribeRendersTarget(t *testing.T) {
	resource, prompt, denyReason, ok := sdbElevateDescribe(sdbElevateWriteSystem, "/etc/hosts")
	if !ok {
		t.Fatalf("describe not ok, denyReason=%q", denyReason)
	}
	if resource != "write-system:/etc/hosts" {
		t.Fatalf("resource=%q, want write-system:/etc/hosts", resource)
	}
	if !strings.Contains(prompt, "/etc/hosts") {
		t.Fatalf("prompt %q does not name the target path", prompt)
	}

	// A plain root shell needs no argument and renders cleanly.
	res, p, _, ok := sdbElevateDescribe(sdbElevateShellRoot, "")
	if !ok || res != sdbElevateShellRoot || !strings.Contains(strings.ToUpper(p), "ROOT") {
		t.Fatalf("root-shell describe wrong: res=%q prompt=%q ok=%v", res, p, ok)
	}
}

// Tier 2: a root shell is refused on a LOCKED (non-rooted) device, before any
// dialog, even under the most permissive scripted policy. Rooting the device is
// the only door to root; a user cannot approve their way past a locked bootloader.
func TestSdbElevateShellRootRefusedOnLockedDevice(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	agent := &mockAgent{lockBody: LockState{Locked: true}}
	startMockAgent(t, agent)
	srv := newElevateServer(t)

	granted, reason := srv.sdbElevate(sdbElevateShellRoot, "", "sess-1", parseOrigin(SDBOrigin("ws")))
	if granted {
		t.Fatal("root shell granted on a locked device, want refused")
	}
	if !strings.Contains(reason, "locked") {
		t.Fatalf("reason=%q, want a 'locked' refusal", reason)
	}
}

// If the lock state cannot be read (no recovery agent), the root shell fails
// closed: an unknown root state is treated as not-rooted, never as rooted.
func TestSdbElevateShellRootRefusedWhenLockStateUnavailable(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	t.Setenv("USH_ATOM_RECOVERY_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	srv := newElevateServer(t)

	granted, reason := srv.sdbElevate(sdbElevateShellRoot, "", "sess-1", parseOrigin(SDBOrigin("ws")))
	if granted {
		t.Fatal("root shell granted with unreadable lock state, want refused")
	}
	if !strings.Contains(reason, "unavailable") {
		t.Fatalf("reason=%q, want an 'unavailable' refusal", reason)
	}
}

// On a ROOTED (unlocked) device the lock gate passes and the decision is the
// human dialog: in headless auto mode there is no user, so it still denies, but
// with the dialog's reason, and only AFTER the lock state was read.
func TestSdbElevateShellRootRootedDeviceReachesDialog(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")
	agent := &mockAgent{lockBody: LockState{Locked: false}}
	startMockAgent(t, agent)
	srv := newElevateServer(t)

	granted, reason := srv.sdbElevate(sdbElevateShellRoot, "", "sess-1", parseOrigin(SDBOrigin("ws")))
	if granted {
		t.Fatal("no user present, want denied at the dialog")
	}
	if strings.Contains(reason, "locked") || strings.Contains(reason, "unavailable") {
		t.Fatalf("reason=%q, want the dialog denial (lock gate should have passed)", reason)
	}
	if agent.callCount() == 0 {
		t.Fatal("lock state was never read on a root-shell request")
	}
}

// Tier 3: an assist session is a bridge action too, so it fails closed with no
// user, and its dialog names it as a bounded read-only assistance session.
func TestSdbElevateAssist(t *testing.T) {
	res, prompt, _, ok := sdbElevateDescribe(sdbElevateAssist, "")
	if !ok || res != sdbElevateAssist || !strings.Contains(strings.ToLower(prompt), "assistance") {
		t.Fatalf("assist describe wrong: res=%q prompt=%q ok=%v", res, prompt, ok)
	}

	t.Setenv("USH_BROKER_AUTO", "allow_always")
	srv := newElevateServer(t)
	granted, _ := srv.sdbElevate(sdbElevateAssist, "", "sess-1", parseOrigin(SDBOrigin("ws")))
	if granted {
		t.Fatal("assist granted with no user present, want denied (fail-closed)")
	}
}

// newElevateServer builds a broker whose auto-decider reflects USH_BROKER_AUTO as
// set by the caller before this runs (NewServer reads it at construction).
func newElevateServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}
