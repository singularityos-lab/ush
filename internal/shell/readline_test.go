// SPDX-License-Identifier: GPL-3.0-or-later

package shell

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func splitKeys(p []byte) ([]string, []byte) {
	var keys []string
	for {
		key, rest, ok := nextKey(p)
		if !ok {
			return keys, p
		}
		keys = append(keys, string(key))
		p = rest
	}
}

func TestNextKeySplitsBurst(t *testing.T) {
	cases := []struct {
		in   string
		keys []string
		left string
	}{
		{"ls\r", []string{"ls", "\r"}, ""},
		{"\x15tr", []string{"\x15", "tr"}, ""},
		{"a\x1b[Ab", []string{"a", "\x1b[A", "b"}, ""},
		{"\x1b[3~x", []string{"\x1b[3~", "x"}, ""},
		{"\x1b[", nil, "\x1b["},
		{"\x1b", []string{"\x1b"}, ""},
		{"caf\xc3", []string{"caf"}, "\xc3"},
		{"caf\xc3\xa8\r", []string{"caf\xc3\xa8", "\r"}, ""},
		{"x\x7fy", []string{"x", "\x7f", "y"}, ""},
	}
	for _, c := range cases {
		keys, left := splitKeys([]byte(c.in))
		if !reflect.DeepEqual(keys, c.keys) || string(left) != c.left {
			t.Errorf("%q: got %q left %q, want %q left %q", c.in, keys, left, c.keys, c.left)
		}
	}
}

func openPty(t *testing.T) (*os.File, *os.File) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Skipf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Skipf("ptsname: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Skipf("open slave: %v", err)
	}
	return master, slave
}

func TestReadlineBurstOnPty(t *testing.T) {
	master, slave := openPty(t)
	defer master.Close()
	defer slave.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = slave, slave
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := master.Read(buf); err != nil {
				return
			}
		}
	}()
	rl := &Readline{}
	if _, err := master.Write([]byte("\x15echo hi\r  cat /proc/cmdline\rcaf\xc3\xa8\r")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"echo hi", "  cat /proc/cmdline", "caf\u00e8"} {
		got, err := rl.Readline("$ ")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}
