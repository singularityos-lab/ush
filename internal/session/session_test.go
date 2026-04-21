// SPDX-License-Identifier: GPL-3.0-or-later

package session

import (
	"testing"
)

func TestSessionLifecycle(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	sess, err := mgr.New(false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if sess.ID == "" {
		t.Error("empty ID")
	}
	if sess.State != StateStarting {
		t.Errorf("State = %q, want starting", sess.State)
	}

	if err := mgr.SetRunning(sess.ID); err != nil {
		t.Fatalf("SetRunning: %v", err)
	}

	sessions := mgr.List()
	if len(sessions) != 1 {
		t.Errorf("List len = %d, want 1", len(sessions))
	}
	if sessions[0].State != StateRunning {
		t.Errorf("State = %q, want running", sessions[0].State)
	}

	if err := mgr.SetStopped(sess.ID); err != nil {
		t.Fatalf("SetStopped: %v", err)
	}

	if err := mgr.Remove(sess.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if len(mgr.List()) != 0 {
		t.Error("List not empty after Remove")
	}
}

func TestMultipleSessions(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	s1, _ := mgr.New(false)
	s2, _ := mgr.New(false)
	s3, _ := mgr.New(true)

	if s1.ID == s2.ID || s2.ID == s3.ID {
		t.Error("session IDs not unique")
	}

	if s3.EphemeralLayerID == "" {
		t.Error("ephemeral session must have EphemeralLayerID")
	}

	list := mgr.List()
	if len(list) != 3 {
		t.Errorf("List len = %d, want 3", len(list))
	}
}

func TestSessionNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	err := mgr.SetRunning("nonexistent")
	if err == nil {
		t.Error("SetRunning on nonexistent session must return an error")
	}
}
