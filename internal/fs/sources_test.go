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

// A crafted option list that mixes our signed-by with a capitalised or spaced
// Trusted=yes must NOT be accepted (case-insensitive, whitespace-tolerant).
func TestEnsureDebianSourcesRejectsCraftedTrusted(t *testing.T) {
	for _, bad := range []string{
		"deb [signed-by=/run/ush/exec/keyrings/debian-archive-keyring.gpg Trusted=yes] http://evil.example/d bookworm main\n",
		"deb [ trusted=yes ] http://evil.example/d bookworm main\n",
		"deb [allow-insecure=yes signed-by=/run/ush/exec/keyrings/debian-archive-keyring.gpg] http://evil.example/d bookworm main\n",
		// signed-by is a comma-separated list: an appended attacker keyring must
		// NOT be accepted just because ours is present.
		"deb [signed-by=/run/ush/exec/keyrings/debian-archive-keyring.gpg,/tmp/evil.gpg] http://evil.example/d bookworm main\n",
	} {
		dir := t.TempDir()
		sl := filepath.Join(dir, "sources.list")
		os.WriteFile(sl, []byte(bad), 0644)
		if changed := ensureDebianSources(dir); !changed {
			t.Fatalf("crafted unsafe source kept: %q", bad)
		}
		out, _ := os.ReadFile(sl)
		if strings.Contains(string(out), "evil.example") {
			t.Fatalf("attacker mirror survived: %q -> %q", bad, string(out))
		}
	}
}

// A malicious file dropped into sources.list.d must be purged, even when the
// main sources.list is already our verified one (which would otherwise return
// early without touching the .d dir).
func TestEnsureDebianSourcesPurgesListD(t *testing.T) {
	dir := t.TempDir()
	good := "deb [signed-by=/run/ush/exec/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm main\n"
	os.WriteFile(filepath.Join(dir, "sources.list"), []byte(good), 0644)
	sd := filepath.Join(dir, "sources.list.d")
	os.MkdirAll(sd, 0755)
	evilList := filepath.Join(sd, "evil.list")
	evilSources := filepath.Join(sd, "evil.sources")
	os.WriteFile(evilList, []byte("deb [trusted=yes] http://evil.example/d sid main\n"), 0644)
	os.WriteFile(evilSources, []byte("Types: deb\nURIs: http://evil.example/d\nSuites: sid\nTrusted: yes\n"), 0644)
	ensureDebianSources(dir)
	if _, err := os.Stat(evilList); err == nil {
		t.Fatal("evil.list survived in sources.list.d")
	}
	if _, err := os.Stat(evilSources); err == nil {
		t.Fatal("evil.sources (deb822) survived in sources.list.d")
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
