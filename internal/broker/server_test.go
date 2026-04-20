// SPDX-License-Identifier: GPL-3.0-or-later

package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/singularityos-lab/ush/internal/policy"
)

func TestAuditLogWrite(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLog(dir)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer al.Close()

	entry := AuditEntry{
		Timestamp: time.Now(),
		SessionID: "test-session",
		Category:  "network",
		Resource:  "outbound",
		Decision:  "allow",
		Source:    "policy_cache",
	}
	al.Write(entry)

	al.Close()

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("log files = %d, want 1", len(files))
	}

	data, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var loaded AuditEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if loaded.Category != "network" {
		t.Errorf("Category = %q, want network", loaded.Category)
	}
	if loaded.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", loaded.Decision)
	}
	if loaded.SessionID != "test-session" {
		t.Errorf("SessionID = %q, want test-session", loaded.SessionID)
	}
}

func TestAuditLogRotation(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLog(dir)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}

	al.Write(AuditEntry{Timestamp: time.Now(), Category: "test1"})
	al.Close()

	al2, err := NewAuditLog(dir)
	if err != nil {
		t.Fatalf("NewAuditLog second open: %v", err)
	}
	al2.Write(AuditEntry{Timestamp: time.Now(), Category: "test2"})
	al2.Close()

	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Errorf("same day: files = %d, want 1", len(files))
	}
}

func TestPortalDialogFallback(t *testing.T) {
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	decision := srv.portalDialog("test.nonexistent", "fallback-test", "test reason")
	if decision != "" {
		t.Skipf("portal responded (likely real broker running): %q", decision)
	}
}

func TestServerPolicyCache(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(dir)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	srv.policy.Set("network", "outbound", policyDecisionAllow)

	decision := srv.requestPermission("network", "outbound", "test", "session-1")
	if decision != "allow" {
		t.Errorf("decision = %q, want allow (from cache)", decision)
	}
}

func TestInflightPermissionWaiterUsesLeaderDecision(t *testing.T) {
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	scope := policy.SuggestScope("network", "tcp://203.0.113.10:443")
	key := permissionInflightKey("network", scope.Resource)
	inflight := &inflightPermission{done: make(chan struct{})}

	srv.mu.Lock()
	srv.inflight[key] = inflight
	srv.mu.Unlock()

	result := make(chan string, 1)
	go func() {
		decision, waited := srv.waitForInflightPermission("network", "tcp://203.0.113.10:443", scope, "session-1")
		if !waited {
			result <- "not-waited"
			return
		}
		result <- decision
	}()

	inflight.decision = "allow_always"
	close(inflight.done)

	select {
	case decision := <-result:
		if decision != "allow" {
			t.Fatalf("decision = %q, want allow", decision)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not unblock")
	}
}

func TestFinalDecisionForWaiters(t *testing.T) {
	tests := map[string]string{
		"allow_always":  "allow",
		"allow_session": "allow",
		"allow":         "allow",
		"deny":          "deny",
		"":              "deny",
	}

	for input, want := range tests {
		if got := finalDecisionForWaiters(input); got != want {
			t.Errorf("finalDecisionForWaiters(%q) = %q, want %q", input, got, want)
		}
	}
}

const policyDecisionAllow = "allow"

func TestDialogSafe(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "/usr/bin/curl", "/usr/bin/curl"},
		{"newline injection", "app\n\nClick Grant to continue", "app  Click Grant to continue"},
		{"crlf", "a\r\nb", "a  b"},
		{"tab", "a\tb", "a b"},
		{"ansi escape", "x\033[2Jy", "x [2Jy"},
		{"nul", "a\x00b", "a b"},
		{"trim", "  hi  ", "hi"},
	}
	for _, c := range cases {
		if got := dialogSafe(c.in); got != c.want {
			t.Errorf("%s: dialogSafe(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}

	// Over-long input is capped and ellipsized so a guest cannot flood the dialog.
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'a'
	}
	got := dialogSafe(string(long))
	if len(got) != 256+3 || got[len(got)-3:] != "..." {
		t.Errorf("long input not capped: len=%d", len(got))
	}
}
