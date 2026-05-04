// SPDX-License-Identifier: GPL-3.0-or-later

package raven

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLayerVFSStat(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	os.MkdirAll(lower, 0755)
	os.MkdirAll(upper, 0755)

	os.WriteFile(filepath.Join(lower, "file.txt"), []byte("lower"), 0644)

	v, err := NewLayerVFS([]string{lower}, upper)
	if err != nil {
		t.Fatalf("NewLayerVFS: %v", err)
	}

	info, err := v.Stat("file.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Name() != "file.txt" {
		t.Errorf("Name = %q, want file.txt", info.Name())
	}
}

func TestLayerVFSReadFile(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	os.MkdirAll(lower, 0755)
	os.MkdirAll(upper, 0755)

	os.WriteFile(filepath.Join(lower, "data.txt"), []byte("from lower"), 0644)

	v, _ := NewLayerVFS([]string{lower}, upper)

	data, err := v.ReadFile("data.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "from lower" {
		t.Errorf("data = %q, want from lower", string(data))
	}
}

func TestLayerVFSWriteFile(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	os.MkdirAll(lower, 0755)
	os.MkdirAll(upper, 0755)

	v, _ := NewLayerVFS([]string{lower}, upper)

	if err := v.WriteFile("new.txt", []byte("written")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := v.ReadFile("new.txt")
	if err != nil {
		t.Fatalf("ReadFile after write: %v", err)
	}
	if string(data) != "written" {
		t.Errorf("data = %q, want written", string(data))
	}
}

func TestLayerVFSRemoveWhiteout(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	os.MkdirAll(lower, 0755)
	os.MkdirAll(upper, 0755)

	os.WriteFile(filepath.Join(lower, "delete-me.txt"), []byte("data"), 0644)

	v, _ := NewLayerVFS([]string{lower}, upper)

	if _, err := v.Stat("delete-me.txt"); err != nil {
		t.Fatalf("Stat before removal: %v", err)
	}

	if err := v.Remove("delete-me.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := v.Stat("delete-me.txt"); err == nil {
		t.Error("Stat after Remove should return an error")
	}
}

func TestLayerVFSListDir(t *testing.T) {
	dir := t.TempDir()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	os.MkdirAll(lower, 0755)
	os.MkdirAll(upper, 0755)

	os.WriteFile(filepath.Join(lower, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(lower, "b.txt"), []byte("b"), 0644)

	v, _ := NewLayerVFS([]string{lower}, upper)
	v.WriteFile("c.txt", []byte("c"))
	v.Remove("b.txt")

	entries, err := v.ListDir("")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}

	names := make(map[string]bool)
	for _, n := range entries {
		names[n] = true
	}

	if !names["a.txt"] {
		t.Error("a.txt must be visible")
	}
	if names["b.txt"] {
		t.Error("b.txt must not be visible (whiteout)")
	}
	if !names["c.txt"] {
		t.Error("c.txt must be visible (upper)")
	}
}
