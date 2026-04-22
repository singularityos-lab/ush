// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package guardsink

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/ush/internal/guardproto"
)

func TestEmitForwardsToSingd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "e.sock")
	t.Setenv("USH_GUARD_EVENTS_SOCK", sock)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan guardproto.Event, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var e guardproto.Event
		if err := json.NewDecoder(conn).Decode(&e); err == nil {
			got <- e
		}
	}()

	New("sess-1").EmitGuardEvent(guardproto.Event{Kind: guardproto.EventExec, PID: 99, Comm: "ls"})

	select {
	case e := <-got:
		if e.Kind != guardproto.EventExec || e.PID != 99 || e.Comm != "ls" {
			t.Errorf("forwarded event mismatch: %+v", e)
		}
		if e.Session != "sess-1" {
			t.Errorf("session not filled in: %q", e.Session)
		}
		if e.Time == "" {
			t.Error("time not filled in")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forwarded event")
	}
}

func TestEmitNeverBlocksWithoutSingd(t *testing.T) {
	t.Setenv("USH_GUARD_EVENTS_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	c := New("s")

	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			c.EmitGuardEvent(guardproto.Event{Kind: guardproto.EventOpen, PID: uint32(i)})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("EmitGuardEvent blocked while singd was absent")
	}
}
