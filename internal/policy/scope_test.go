// SPDX-License-Identifier: GPL-3.0-or-later

package policy

import "testing"

func TestSuggestFilesystemScopeUsesLocalParent(t *testing.T) {
	scope := SuggestScope("filesystem", "read:/repo/src/components/Button.tsx")

	if scope.Resource != "read:/repo/src/components/" {
		t.Fatalf("scope resource = %q, want read:/repo/src/components/", scope.Resource)
	}
	if scope.Exact {
		t.Fatal("scope should be parent directory, not exact")
	}
}

func TestSuggestFilesystemScopeKeepsSensitivePathsExact(t *testing.T) {
	tests := []string{
		"read:/repo/.env",
		"read:/home/user/.ssh/id_ed25519",
		"read:/repo/config/token.json",
	}

	for _, resource := range tests {
		scope := SuggestScope("filesystem", resource)
		if scope.Resource != resource {
			t.Errorf("scope resource for %q = %q, want exact", resource, scope.Resource)
		}
		if !scope.Exact {
			t.Errorf("scope for %q should be exact", resource)
		}
	}
}

func TestSuggestFilesystemScopeDoesNotWidenDangerousBoundaries(t *testing.T) {
	scope := SuggestScope("filesystem", "read:/etc/hosts")

	if scope.Resource != "read:/etc/hosts" {
		t.Fatalf("scope resource = %q, want read:/etc/hosts", scope.Resource)
	}
	if !scope.Exact {
		t.Fatal("scope should be exact at dangerous boundary")
	}
}

func TestSuggestFilesystemScopeKeepsWritesExact(t *testing.T) {
	scope := SuggestScope("filesystem", "write:/repo/src/generated/file.go")

	if scope.Resource != "write:/repo/src/generated/file.go" {
		t.Fatalf("scope resource = %q, want exact write resource", scope.Resource)
	}
	if !scope.Exact {
		t.Fatal("write scope should be exact")
	}
}

func TestPolicyScopedFilesystemMatch(t *testing.T) {
	eng, err := NewEngine(t.TempDir() + "/policy.json")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	eng.Set("filesystem", "read:/repo/src/components/", DecisionAllow)

	decision, ok := eng.Check("filesystem", "read:/repo/src/components/Button.tsx")
	if !ok || decision != DecisionAllow {
		t.Fatalf("scoped decision = %q ok=%v, want allow true", decision, ok)
	}

	if _, ok := eng.Check("filesystem", "read:/repo/src2/Button.tsx"); ok {
		t.Fatal("scope must not match sibling path with same prefix")
	}
}

func TestPolicyScopedFilesystemOperationMustMatch(t *testing.T) {
	eng, err := NewEngine(t.TempDir() + "/policy.json")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	eng.Set("filesystem", "read:/repo/src/", DecisionAllow)

	if _, ok := eng.Check("filesystem", "write:/repo/src/file.go"); ok {
		t.Fatal("read scope must not allow write request")
	}
}

func TestSuggestNetworkScopeKeepsEndpointBounded(t *testing.T) {
	scope := SuggestScope("network", "tcp://140.82.112.5:443")

	if scope.Resource != "tcp://140.82.112.5:443" {
		t.Fatalf("scope resource = %q, want endpoint", scope.Resource)
	}
	if scope.Exact {
		t.Fatal("network endpoint is reusable but still host+port bounded")
	}
}

func TestPolicyScopedNetworkMatchIgnoresURLPathOnly(t *testing.T) {
	eng, err := NewEngine(t.TempDir() + "/policy.json")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	eng.Set("network", "https://api.github.com", DecisionAllow)

	decision, ok := eng.Check("network", "https://api.github.com/repos/x/y")
	if !ok || decision != DecisionAllow {
		t.Fatalf("network decision = %q ok=%v, want allow true", decision, ok)
	}

	if _, ok := eng.Check("network", "https://uploads.github.com/repos/x/y"); ok {
		t.Fatal("network scope must not match a different host")
	}
}

func TestSuggestNetworkScopeRejectsOutboundWidening(t *testing.T) {
	scope := SuggestScope("network", "outbound")

	if scope.Resource != "outbound" || !scope.Exact || scope.Risk != RiskHigh {
		t.Fatalf("scope = %#v, want exact high-risk outbound", scope)
	}
}
