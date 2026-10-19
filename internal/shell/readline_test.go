// SPDX-License-Identifier: GPL-3.0-or-later

package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
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
		{"\x1bbx", []string{"\x1bb", "x"}, ""},
		{"\x1bOHx", []string{"\x1bOH", "x"}, ""},
		{"\x1bO", nil, "\x1bO"},
		{"\x1b\x7f", []string{"\x1b\x7f"}, ""},
		{"\x1b[1;5D", []string{"\x1b[1;5D"}, ""},
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

func readOnPty(t *testing.T, rl *Readline, input string) string {
	t.Helper()
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
	if _, err := term.MakeRaw(int(slave.Fd())); err != nil {
		t.Fatal(err)
	}
	if _, err := master.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	got, err := rl.Readline("$ ")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReadlineBindingsOnPty(t *testing.T) {
	complete := func(line string, pos int) (string, []string, string) {
		word := line[strings.LastIndex(line[:pos], " ")+1 : pos]
		var out []string
		for _, c := range []string{"install", "inspect", "install"} {
			if strings.HasPrefix(c, word) {
				out = append(out, c)
			}
		}
		return line[:pos-len(word)], out, line[pos:]
	}
	cases := []struct {
		name    string
		history []string
		input   string
		want    string
	}{
		{"reverse search", []string{"ls -la", "git status", "echo hello"}, "\x12git\r", "git status"},
		{"reverse search again", []string{"git log", "git status"}, "\x12git\x12\r", "git log"},
		{"search then edit", []string{"git status"}, "\x12stat\x05 -s\r", "git status -s"},
		{"search then arrow", []string{"git status"}, "\x12git\x1b[DX\r", "Xgit status"},
		{"search cancel", []string{"git status"}, "abc\x12git\x07\r", "abc"},
		{"search failed keeps match", []string{"git status"}, "\x12gitzz\r", "git status"},
		{"search backspace", []string{"echo hello", "ls"}, "\x12echx\x7f\r", "echo hello"},
		{"search escape keeps match", []string{"git status"}, "\x12git\x1b\r", "git status"},
		{"forward search", []string{"git log", "git status"}, "\x12git\x12\x13\r", "git status"},
		{"alt word moves", nil, "one two three\x1bb\x1bbX\x1bf\x1bfY\r", "one Xtwo threeY"},
		{"ctrl arrows", nil, "one two\x1b[1;5DX\x1b[1;5CY\r", "one XtwoY"},
		{"home end variants", nil, "bc\x1b[1~a\x1b[4~d\x1bOHz\x1bOF!\r", "zabcd!"},
		{"kill and yank", nil, "foo bar\x17\x01\x19 \r", "bar foo "},
		{"kill to end and yank", nil, "abc def\x01\x1bf\x0b\x01\x19\r", " defabc"},
		{"alt d", nil, "one two\x01\x1bd\r", " two"},
		{"alt backspace", nil, "one two\x1b\x7f\r", "one "},
		{"transpose", nil, "ab\x14\r", "ba"},
		{"last argument", []string{"cat /etc/os-release"}, "less \x1b.\r", "less /etc/os-release"},
		{"last argument cycles", []string{"cp a b", "cat c"}, "x \x1b.\x1b.\r", "x b"},
		{"history ctrl p n", []string{"a", "b"}, "\x10\x10\x0e\r", "b"},
		{"history ends", []string{"a", "b"}, "typed\x1b<\x1b>\r", "typed"},
		{"char moves", nil, "ac\x02b\x06d\r", "abcd"},
		{"ctrl d deletes", nil, "abc\x01\x04\r", "bc"},
		{"tab common prefix", nil, "in\t\r", "ins"},
		{"tab unique", nil, "insp\t\r", "inspect"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rl := &Readline{history: append([]string{}, c.history...), completion: complete}
			if got := readOnPty(t, rl, c.input); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestHistoryIsWrittenRightAway(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sub", "shell_history")
	rl, _ := newReadline(file, nil)
	rl.addHistory("first")
	rl.addHistory("first")
	other, _ := newReadline(file, nil)
	other.addHistory("second")
	rl.addHistory("third")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\nsecond\nthird\n" {
		t.Fatalf("history file = %q", data)
	}
	again, _ := newReadline(file, nil)
	if !reflect.DeepEqual(again.history, []string{"first", "second", "third"}) {
		t.Fatalf("reloaded history = %q", again.history)
	}
}
