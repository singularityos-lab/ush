// SPDX-License-Identifier: GPL-3.0-or-later
package fs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pre-existing or attacker-planted [trusted=yes] source must NOT survive:
// ensureDebianSources has to rewrite it with the signed-by, keyring-verified
// version instead of accepting it (which would bypass apt signature checks).
func TestEnsureDebianSourcesRejectsTrusted(t *testing.T) {
	dir := t.TempDir()
	sl := filepath.Join(dir, "sources.list")
	if err := os.WriteFile(sl, []byte("deb [trusted=yes] http://evil.example/debian sid main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if changed := ensureDebianSources(dir); !changed {
		t.Fatal("expected ensureDebianSources to REWRITE a trusted=yes source, but it kept it")
	}
	out, _ := os.ReadFile(sl)
	s := string(out)
	if strings.Contains(s, "trusted=yes") {
		t.Fatalf("trusted=yes survived the rewrite: %q", s)
	}
	if strings.Contains(s, "evil.example") {
		t.Fatalf("attacker mirror survived the rewrite: %q", s)
	}
	if !strings.Contains(s, "signed-by=/run/ush/exec/keyrings/debian-archive-keyring.gpg") {
		t.Fatalf("rewritten source is not signed-by verified: %q", s)
	}
}

// A sources.list already pinned to our signed-by keyring is safe and must be
// kept as-is (no needless re-download).
func TestEnsureDebianSourcesKeepsVerified(t *testing.T) {
	dir := t.TempDir()
	sl := filepath.Join(dir, "sources.list")
	good := "deb [signed-by=/run/ush/exec/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm main\n"
	if err := os.WriteFile(sl, []byte(good), 0644); err != nil {
		t.Fatal(err)
	}
	if changed := ensureDebianSources(dir); changed {
		t.Fatal("expected a signed-by source to be kept, but it was rewritten")
	}
}
