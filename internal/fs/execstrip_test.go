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
