// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package scope

import "testing"

func TestSanitize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"code", "code"},
		{"google-chrome", "google-chrome"},
		{"py_thon3", "py_thon3"},
		{"weird name!@#", "weird-name"},
		{"/usr/bin/foo", "usr-bin-foo"},
		{"", "app"},
		{"---", "app"},
		{"héllo", "h-llo"},
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeCapsLength(t *testing.T) {
	long := ""
	for i := 0; i < 60; i++ {
		long += "a"
	}
	if got := sanitize(long); len(got) != 40 {
		t.Errorf("sanitize did not cap length: got %d chars", len(got))
	}
}
