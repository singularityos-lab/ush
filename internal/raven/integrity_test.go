// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package raven

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashLayerSkipsWhiteoutsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "usr/bin/foo"), "hello")
	mustWrite(t, filepath.Join(dir, "usr/bin/.wh.removed"), "")
	if err := os.Symlink("foo", filepath.Join(dir, "usr/bin/link")); err != nil {
		t.Fatal(err)
	}

	h, err := HashLayer(dir)
	if err != nil {
		t.Fatalf("HashLayer: %v", err)
	}
	if _, ok := h["/usr/bin/foo"]; !ok {
		t.Errorf("expected /usr/bin/foo in hashes, got %v", h)
	}
	if _, ok := h["/usr/bin/.wh.removed"]; ok {
		t.Errorf("whiteout should be skipped")
	}
	if _, ok := h["/usr/bin/link"]; ok {
		t.Errorf("symlink should be skipped")
	}
}

func TestDiffAgainstBaseline(t *testing.T) {
	layer := t.TempDir()
	// /usr/bin/sh: same path as baseline, different content -> modified
	mustWrite(t, filepath.Join(layer, "usr/bin/sh"), "TAMPERED")
	// /usr/lib/keep.so: same path, same content -> shadowed but not modified
	mustWrite(t, filepath.Join(layer, "usr/lib/keep.so"), "unchanged")
	// /opt/app/new: not in baseline -> new
	mustWrite(t, filepath.Join(layer, "opt/app/new"), "brand new")

	keepHash, err := sha256File(filepath.Join(layer, "usr/lib/keep.so"))
	if err != nil {
		t.Fatal(err)
	}

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	mustWrite(t, baselinePath, `{
		"files": {
			"/usr/bin/sh": "0000000000000000000000000000000000000000000000000000000000000000",
			"/usr/lib/keep.so": "`+keepHash+`"
		}
	}`)

	diff, err := DiffAgainstBaseline(layer, baselinePath)
	if err != nil {
		t.Fatalf("DiffAgainstBaseline: %v", err)
	}

	if got := join(diff.Shadowed); got != "/usr/bin/sh,/usr/lib/keep.so" {
		t.Errorf("shadowed = %q", got)
	}
	if got := join(diff.Modified); got != "/usr/bin/sh" {
		t.Errorf("modified = %q, want /usr/bin/sh", got)
	}
	if got := join(diff.New); got != "/opt/app/new" {
		t.Errorf("new = %q, want /opt/app/new", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
