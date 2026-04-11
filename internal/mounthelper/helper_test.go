// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package mounthelper

import (
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/ush/internal/policy"
)

func TestSocketPath(t *testing.T) {
	got := SocketPath("/run/user/1000", "abc123")
	want := "/run/user/1000/ush/mount-helper-abc123.sock"
	if got != want {
		t.Errorf("SocketPath = %q, want %q", got, want)
	}
}

func TestIsTrusted(t *testing.T) {
	dir := t.TempDir()
	eng, err := policy.NewEngine(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	eng.Set(policy.Category("devdir"), "/home/x/Projects", policy.DecisionAllow)
	if err := eng.Save(); err != nil {
		t.Fatal(err)
	}

	h := &helper{storageDir: dir}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/x/Projects", true},          // exact grant
		{"/home/x/Projects/sub/deep", true}, // below the grant
		{"/home/x/Projectsevil", false},     // prefix trick must not match
		{"/home/x/Other", false},            // unrelated
		{"/etc/passwd", false},              // outside any grant
	}
	for _, c := range cases {
		if got := h.isTrusted(c.path); got != c.want {
			t.Errorf("isTrusted(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsTrustedNoPolicy(t *testing.T) {
	h := &helper{storageDir: t.TempDir()} // no policy.json written
	if h.isTrusted("/home/x/Projects") {
		t.Error("isTrusted should be false with no policy grants")
	}
}
