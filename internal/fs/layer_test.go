// SPDX-License-Identifier: GPL-3.0-or-later

package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLayerManagerPersistent(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)

	layer, err := lm.EnsurePersistent()
	if err != nil {
		t.Fatalf("EnsurePersistent: %v", err)
	}
	if layer.ID != "persistent" {
		t.Errorf("ID = %q, want persistent", layer.ID)
	}
	if layer.Type != LayerPersistent {
		t.Errorf("Type = %q, want persistent", layer.Type)
	}

	if _, err := os.Stat(layer.UpperDir); err != nil {
		t.Errorf("upper dir not created: %v", err)
	}
}

func TestLayerManagerEphemeral(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)

	layer, err := lm.NewEphemeral("sess-123")
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	if layer.ID != "ephemeral-sess-123" {
		t.Errorf("ID = %q, want ephemeral-sess-123", layer.ID)
	}
	if layer.Type != LayerEphemeral {
		t.Errorf("Type = %q, want ephemeral", layer.Type)
	}
	if layer.SessionID != "sess-123" {
		t.Errorf("SessionID = %q, want sess-123", layer.SessionID)
	}
}

func TestLayerManagerRemoveEphemeral(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)

	lm.NewEphemeral("sess-456")
	ephemPath := filepath.Join(dir, "layers", "ephemeral", "sess-456")
	if _, err := os.Stat(ephemPath); os.IsNotExist(err) {
		t.Fatalf("ephemeral dir not created")
	}

	if err := lm.RemoveEphemeral("sess-456"); err != nil {
		t.Fatalf("RemoveEphemeral: %v", err)
	}

	if _, err := os.Stat(ephemPath); !os.IsNotExist(err) {
		t.Error("ephemeral dir not removed after RemoveEphemeral")
	}
}

func TestLayerManagerManifest(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)
	lm.EnsurePersistent()

	if err := lm.AddPackage("htop"); err != nil {
		t.Fatalf("AddPackage: %v", err)
	}
	if err := lm.AddPackage("vim"); err != nil {
		t.Fatalf("AddPackage: %v", err)
	}

	pkgs, err := lm.ListPackages()
	if err != nil {
		t.Fatalf("ListPackages: %v", err)
	}
	if len(pkgs) != 2 {
		t.Errorf("len = %d, want 2", len(pkgs))
	}

	if err := lm.RemovePackage("htop"); err != nil {
		t.Fatalf("RemovePackage: %v", err)
	}

	pkgs, _ = lm.ListPackages()
	if len(pkgs) != 1 || pkgs[0] != "vim" {
		t.Errorf("after remove: pkgs = %v, want [vim]", pkgs)
	}
}

func TestLayerManagerAddPackageIdempotent(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)
	lm.EnsurePersistent()

	lm.AddPackage("htop")
	lm.AddPackage("htop")

	pkgs, _ := lm.ListPackages()
	count := 0
	for _, p := range pkgs {
		if p == "htop" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("htop appears %d times, want 1", count)
	}
}

func TestLayerManagerDiff(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)
	lm.EnsurePersistent()

	upperDir := lm.PersistentUpper()
	os.MkdirAll(filepath.Join(upperDir, "usr", "bin"), 0755)
	os.WriteFile(filepath.Join(upperDir, "usr", "bin", "custom"), []byte("bin"), 0755)

	files, err := lm.Diff()
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(files) == 0 {
		t.Error("Diff should return files in the upper layer")
	}
}

func TestLayerManagerFreezeEphemeral(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)
	lm.EnsurePersistent()

	ephem, err := lm.NewEphemeral("sess-freeze")
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}

	testFile := filepath.Join(ephem.UpperDir, "test.txt")
	os.MkdirAll(ephem.UpperDir, 0755)
	os.WriteFile(testFile, []byte("ephemeral data"), 0644)

	if err := lm.FreezeEphemeral("sess-freeze"); err != nil {
		t.Fatalf("FreezeEphemeral: %v", err)
	}

	persistentFile := filepath.Join(lm.PersistentUpper(), "test.txt")
	data, err := os.ReadFile(persistentFile)
	if err != nil {
		t.Fatalf("file not copied to persistent layer: %v", err)
	}
	if string(data) != "ephemeral data" {
		t.Errorf("content = %q, want ephemeral data", string(data))
	}
}

func TestLayerPkgRootDir(t *testing.T) {
	dir := t.TempDir()
	lm := NewLayerManager(dir)

	expected := filepath.Join(dir, "layers", "persistent", "pkgroot")
	if lm.PkgRootDir() != expected {
		t.Errorf("PkgRootDir = %q, want %q", lm.PkgRootDir(), expected)
	}
}
