// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeDecision(t *testing.T) {
	cases := map[string]string{
		"allow":         "allow",
		"ALLOW":         "allow",
		"  deny  ":      "deny",
		"allow_always":  "allow_always",
		"allow_session": "allow_session",
		"garbage":       "deny", // unrecognized fails safe
		"":              "deny",
	}
	for in, want := range cases {
		if got := normalizeDecision(in); got != want {
			t.Errorf("normalizeDecision(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRuleMatching(t *testing.T) {
	rules := []*Rule{
		{Category: "network", Resource: "tcp://1.1.1.1:443", Match: "exact", Decision: "allow"},
		{Category: "network", Resource: "tcp://10.", Match: "prefix", Decision: "deny"},
		{Category: "device", Resource: "sd", Match: "substr", Decision: "deny"},
		{Category: "", Resource: "secret", Match: "substr", Decision: "deny"}, // any category
	}

	tests := []struct {
		idx      int
		category string
		resource string
		want     bool
	}{
		{0, "network", "tcp://1.1.1.1:443", true},
		{0, "network", "tcp://1.1.1.1:80", false},
		{0, "NETWORK", "tcp://1.1.1.1:443", true}, // category case-insensitive
		{1, "network", "tcp://10.0.0.5:22", true},
		{1, "network", "tcp://11.0.0.5:22", false},
		{2, "device", "/dev/sda", true},
		{2, "network", "/dev/sda", false}, // category must match
		{3, "anything", "my-secret-token", true},
	}
	for _, tc := range tests {
		if got := rules[tc.idx].matches(tc.category, tc.resource); got != tc.want {
			t.Errorf("rule[%d].matches(%q,%q) = %v, want %v",
				tc.idx, tc.category, tc.resource, got, tc.want)
		}
	}
}

func TestDeciderDefaultAndRules(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	rules := []Rule{
		{Category: "network", Resource: "tcp://1.1.1.1:443", Match: "exact", Decision: "allow"},
	}
	data, _ := json.Marshal(rules)
	if err := os.WriteFile(rulesPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, "decisions.jsonl")
	t.Setenv("USH_BROKER_AUTO", "deny")
	t.Setenv("USH_BROKER_RULES", rulesPath)
	t.Setenv("USH_BROKER_DECISION_LOG", logPath)
	t.Setenv("USH_BROKER_CONFIRM", "no")

	d := newAutoDecider()
	if !d.enabled {
		t.Fatal("decider should be enabled when USH_BROKER_AUTO is set")
	}

	// Matching rule wins over the default.
	if got := d.decide("network", "tcp://1.1.1.1:443", "test"); got != "allow" {
		t.Errorf("rule match: got %q, want allow", got)
	}
	// No rule matches => default verdict.
	if got := d.decide("network", "tcp://8.8.8.8:443", "test"); got != "deny" {
		t.Errorf("default: got %q, want deny", got)
	}
	// Confirmation gate defaults to refuse.
	if d.confirmVerdict("confirm", "trust app") {
		t.Error("confirmVerdict should be false when USH_BROKER_CONFIRM != yes")
	}

	// The decision log must have recorded the two permission decisions plus the
	// confirm, i.e. three lines.
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range logged {
		if b == '\n' {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("decision log has %d lines, want 3:\n%s", lines, logged)
	}
}

func TestDeciderDisabledWithoutEnv(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "")
	d := newAutoDecider()
	if d.enabled {
		t.Error("decider must be disabled when USH_BROKER_AUTO is unset")
	}
}
