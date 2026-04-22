// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package guardproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSocketEnvOverride(t *testing.T) {
	t.Setenv("USH_GUARD_EVENTS_SOCK", "/tmp/custom-events.sock")
	t.Setenv("USH_GUARD_CTL_SOCK", "/tmp/custom-ctl.sock")
	if got := EventsSocket(); got != "/tmp/custom-events.sock" {
		t.Errorf("EventsSocket override = %q", got)
	}
	if got := ControlSocket(); got != "/tmp/custom-ctl.sock" {
		t.Errorf("ControlSocket override = %q", got)
	}
}

func TestSocketDefaultUsesRuntimeDir(t *testing.T) {
	t.Setenv("USH_GUARD_EVENTS_SOCK", "")
	t.Setenv("USH_GUARD_CTL_SOCK", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/4242")
	if got := EventsSocket(); got != "/run/user/4242/singd-events.sock" {
		t.Errorf("EventsSocket default = %q", got)
	}
	if got := ControlSocket(); got != "/run/user/4242/singd-control.sock" {
		t.Errorf("ControlSocket default = %q", got)
	}
}

func TestEventOmitsEmptyFields(t *testing.T) {
	data, err := json.Marshal(Event{Kind: EventExec, PID: 7, Time: "t"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, absent := range []string{"comm", "path", "dest", "detail", "session"} {
		if strings.Contains(s, absent) {
			t.Errorf("expected %q to be omitted, got %s", absent, s)
		}
	}
	if !strings.Contains(s, `"kind":"exec"`) || !strings.Contains(s, `"pid":7`) {
		t.Errorf("required fields missing: %s", s)
	}
}

func TestRequestResponseRoundTrip(t *testing.T) {
	req := Request{Cmd: "scan", Args: []string{"/home/x"}}
	data, _ := json.Marshal(req)
	var got Request
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Cmd != "scan" || len(got.Args) != 1 || got.Args[0] != "/home/x" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}
