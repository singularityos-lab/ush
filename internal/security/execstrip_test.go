// SPDX-License-Identifier: GPL-3.0-or-later

package security

import "testing"

func TestPathHasPrefix(t *testing.T) {
	prefixes := []string{"/home/user/Downloads", "/home/user/Documents"}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/user/Downloads/evil.sh", true},
		{"/home/user/Downloads", true},
		{"/home/user/Downloads/sub/x", true},
		{"/home/user/Documents/a", true},
		{"/home/user/DownloadsEvil/x", false}, // prefix must be a path boundary
		{"/home/user/Projects/personal/ush/build", false},
		{"/etc/passwd", false},
		{"", false},
		// ostree /var/home alias must still match a /home prefix.
		{"/var/home/user/Downloads/evil.sh", true},
	}
	for _, c := range cases {
		if got := pathHasPrefix(c.path, prefixes); got != c.want {
			t.Errorf("pathHasPrefix(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	// And a /var/home prefix must match a /home path (both directions).
	if !pathHasPrefix("/home/user/Downloads/x", []string{"/var/home/user/Downloads"}) {
		t.Error("/var/home prefix must match /home path after normalization")
	}
	if pathHasPrefix("/anything", nil) {
		t.Error("nil prefixes must match nothing")
	}
}

func TestExecBitMask(t *testing.T) {
	// The handler clears setuid/setgid/sticky and all execute bits, keeping rw.
	cases := map[uint32]uint32{
		0o755:  0o644,
		0o4755: 0o644,
		0o2750: 0o640,
		0o700:  0o600,
		0o777:  0o666,
	}
	for in, want := range cases {
		got := in &^ 0o7111 & 0o777
		if got != want {
			t.Errorf("mask(%#o) = %#o, want %#o", in, got, want)
		}
		if got&0o7111 != 0 {
			t.Errorf("mask(%#o) still has exec/suid bits: %#o", in, got)
		}
	}
}
