// SPDX-License-Identifier: GPL-3.0-or-later

package fuse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFUSEBackendCOW(t *testing.T) {
	dir := t.TempDir()
	upper := filepath.Join(dir, "upper")
	lower := filepath.Join(dir, "lower")

	os.MkdirAll(upper, 0755)
	os.MkdirAll(lower, 0755)

	// Write a file in the lower layer.
	os.WriteFile(filepath.Join(lower, "hello.txt"), []byte("hello from lower"), 0644)

	b := NewFUSEBackend(upper)
	b.AddLowerLayer(lower)

	// Read from the lower layer.
	data, err := b.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("ReadFile from lower layer: %v", err)
	}
	if string(data) != "hello from lower" {
		t.Errorf("data = %q, want %q", data, "hello from lower")
	}

	// Write to the upper layer (COW).
	if err := b.WriteFile("hello.txt", []byte("hello from upper"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Now the upper layer must take precedence.
	data, err = b.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("ReadFile after COW: %v", err)
	}
	if string(data) != "hello from upper" {
		t.Errorf("COW: data = %q, want %q", data, "hello from upper")
	}

	// The lower layer must not be modified.
	lowerData, _ := os.ReadFile(filepath.Join(lower, "hello.txt"))
	if string(lowerData) != "hello from lower" {
		t.Error("COW: lower layer was modified")
	}
}

func TestFUSEBackendWhiteout(t *testing.T) {
	dir := t.TempDir()
	upper := filepath.Join(dir, "upper")
	lower := filepath.Join(dir, "lower")

	os.MkdirAll(upper, 0755)
	os.MkdirAll(lower, 0755)
	os.WriteFile(filepath.Join(lower, "delete-me.txt"), []byte("data"), 0644)

	b := NewFUSEBackend(upper)
	b.AddLowerLayer(lower)

	// Stat before removal.
	if _, err := b.Stat("delete-me.txt"); err != nil {
		t.Fatalf("Stat before removal: %v", err)
	}

	// Remove (creates whiteout).
	if err := b.Remove("delete-me.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Now it must be invisible.
	if _, err := b.Stat("delete-me.txt"); !os.IsNotExist(err) {
		t.Error("after Remove: Stat should return ErrNotExist")
	}

	// The lower layer must not be modified by Remove.
	if _, err := os.Stat(filepath.Join(lower, "delete-me.txt")); err != nil {
		t.Error("lower layer must not be modified by Remove")
	}
}

func TestFUSEBackendListDir(t *testing.T) {
	dir := t.TempDir()
	upper := filepath.Join(dir, "upper")
	lower := filepath.Join(dir, "lower")

	os.MkdirAll(upper, 0755)
	os.MkdirAll(lower, 0755)

	os.WriteFile(filepath.Join(lower, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(lower, "b.txt"), []byte("b"), 0644)

	b := NewFUSEBackend(upper)
	b.AddLowerLayer(lower)

	// Add a file in the upper layer.
	b.WriteFile("c.txt", []byte("c"), 0644)

	// Remove b.txt (whiteout).
	b.Remove("b.txt")

	entries, err := b.ListDir("")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
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

func TestFUSEBackendType(t *testing.T) {
	b := NewFUSEBackend("/tmp")
	if b.Type() != BackendFUSE {
		t.Errorf("Type = %q, want fuse", b.Type())
	}
}
