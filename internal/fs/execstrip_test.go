// SPDX-License-Identifier: GPL-3.0-or-later

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

// Home data dirs are now write-isolated (overlay), so they are NOT raw host
// read-write and must NOT appear in the exec-strip list. Only an explicit :rw
// extra bind is a raw host surface that needs stripping.
func TestHostBackedRWGuestPathsOnlyRawBinds(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, "Downloads"))
	proj := filepath.Join(home, "Projects", "demo")
	mustMkdir(t, proj)
	t.Setenv("USH_START_CWD", proj)

	g := &GuestFS{
		HomeDir:    home,
		ExtraBinds: []string{"/opt/data:/opt/data:rw", "/opt/ro:/opt/ro:ro"},
	}
	got := g.HostBackedRWGuestPaths()

	has := func(p string) bool {
		for _, x := range got {
			if x == p {
				return true
			}
		}
		return false
	}

	if has(filepath.Join(home, "Downloads")) || has(proj) {
		t.Errorf("overlay'd data dirs must NOT be in the raw exec-strip list; got %v", got)
	}
	if !has("/opt/data") {
		t.Errorf(":rw extra bind must be exec-stripped; got %v", got)
	}
	if has("/opt/ro") {
		t.Errorf(":ro extra bind is not writable; must not be listed; got %v", got)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Fatal(err)
	}
}

// In the developer shell the personal data dirs are bound raw read-write so the
// host sees what tools save there, which puts them in the exec-strip list.
func TestDevProfileSharesDataDirsRaw(t *testing.T) {
	home := t.TempDir()
	g := &GuestFS{HomeDir: home, DevProfile: true}
	got := g.HostBackedRWGuestPaths()
	for _, sub := range []string{"Documents", "Downloads"} {
		found := false
		for _, x := range got {
			if x == filepath.Join(home, sub) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s must be exec-stripped in the developer shell; got %v", sub, got)
		}
	}
	if !g.isSharedDataDir("Downloads") || g.isSharedDataDir("Projects") {
		t.Error("only the personal data dirs are shared raw")
	}
	if (&GuestFS{HomeDir: home}).isSharedDataDir("Downloads") {
		t.Error("the secure shell keeps data dirs write-isolated")
	}
}

func TestMigrateIsolatedWritesMovesNewFiles(t *testing.T) {
	root := t.TempDir()
	host := filepath.Join(root, "host", "Downloads")
	mustMkdir(t, host)
	g := &GuestFS{GuestRoot: filepath.Join(root, "guest"), LayerDir: filepath.Join(root, "layers"), DevProfile: true}
	dst := filepath.Join(g.GuestRoot, host)
	upper := filepath.Join(g.overlayBase(dst), "upper")
	mustMkdir(t, filepath.Join(upper, "sub"))
	if err := os.WriteFile(filepath.Join(upper, "sub", "new.md"), []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upper, "same.md"), []byte("guest"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "same.md"), []byte("host"), 0o644); err != nil {
		t.Fatal(err)
	}

	g.migrateIsolatedWrites(host, dst)

	fi, err := os.Stat(filepath.Join(host, "sub", "new.md"))
	if err != nil {
		t.Fatalf("new file not moved to the host: %v", err)
	}
	if fi.Mode()&0o111 != 0 {
		t.Errorf("moved file kept its executable bit: %v", fi.Mode())
	}
	if data, _ := os.ReadFile(filepath.Join(host, "same.md")); string(data) != "host" {
		t.Errorf("a host file was overwritten: %q", data)
	}
	if _, err := os.Stat(filepath.Join(upper, "same.md")); err != nil {
		t.Errorf("the conflicting guest copy must stay in the layer: %v", err)
	}
}
