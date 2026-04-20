// SPDX-License-Identifier: GPL-3.0-or-later

package policy

import (
	"os"
	"testing"
)

func TestPolicyEngine(t *testing.T) {
	path := t.TempDir() + "/policy.json"

	eng, err := NewEngine(path)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Test: unconfigured category -> ASK
	d, ok := eng.Check(CategoryFileOutsideGuest, "/mnt/data")
	if ok {
		t.Error("should not find rule for unconfigured category")
	}
	if d != DecisionAsk {
		t.Errorf("default decision = %q, want ask", d)
	}

	// Test: set ALLOW rule
	eng.Set(CategoryFileOutsideGuest, "/mnt/data", DecisionAllow)
	d, ok = eng.Check(CategoryFileOutsideGuest, "/mnt/data")
	if !ok {
		t.Error("should find rule")
	}
	if d != DecisionAllow {
		t.Errorf("decision = %q, want allow", d)
	}

	// Test: wildcard
	eng.Set(CategoryNotifications, "*", DecisionAllow)
	d, ok = eng.Check(CategoryNotifications, "org.example.App")
	if !ok {
		t.Error("wildcard: should find rule")
	}
	if d != DecisionAllow {
		t.Errorf("wildcard decision = %q, want allow", d)
	}

	// Test: save and reload
	if err := eng.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	eng2, err := NewEngine(path)
	if err != nil {
		t.Fatalf("NewEngine reload: %v", err)
	}
	d, ok = eng2.Check(CategoryFileOutsideGuest, "/mnt/data")
	if !ok || d != DecisionAllow {
		t.Errorf("reload: decision = %q (ok=%v), want allow (true)", d, ok)
	}
}

func TestPolicyRemove(t *testing.T) {
	path := t.TempDir() + "/policy.json"
	eng, _ := NewEngine(path)

	eng.Set(CategoryDeviceAccess, "/dev/kvm", DecisionDeny)
	eng.Remove(CategoryDeviceAccess, "/dev/kvm")

	_, ok := eng.Check(CategoryDeviceAccess, "/dev/kvm")
	if ok {
		t.Error("after Remove should not find rule")
	}
}

func TestPolicyList(t *testing.T) {
	path := t.TempDir() + "/policy.json"
	eng, _ := NewEngine(path)

	eng.Set(CategoryNetElevated, "vpn0", DecisionAllow)
	eng.Set(CategoryMountSpecial, "/mnt/usb", DecisionDeny)

	rules := eng.List()
	// There are also default rules (notifications, portal).
	if len(rules) < 2 {
		t.Errorf("List len = %d, want >= 2", len(rules))
	}
}

func TestPolicyFileNotExist(t *testing.T) {
	path := t.TempDir() + "/nonexistent/policy.json"
	eng, err := NewEngine(path)
	if err != nil {
		t.Fatalf("NewEngine with non-existent file: %v", err)
	}
	// Must have default rules.
	d, ok := eng.Check(CategoryNotifications, "*")
	if !ok || d != DecisionAllow {
		t.Errorf("notifications default: d=%q ok=%v, want allow/true", d, ok)
	}
}

var _ = os.Remove
