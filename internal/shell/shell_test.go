// SPDX-License-Identifier: GPL-3.0-or-later

package shell

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

func TestPrompt(t *testing.T) {
	sh := &Shell{}
	p := sh.prompt()

	if !strings.Contains(p, "USH") {
		t.Error("prompt must contain 'USH'")
	}
	if !strings.Contains(p, "$") {
		t.Error("prompt must contain '$'")
	}
}

func TestLastWord(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"hello", "hello"},
		{"ls -la", "-la"},
		{"pkg install htop", "htop"},
	}

	for _, tt := range tests {
		got := lastWord(tt.input)
		if got != tt.want {
			t.Errorf("lastWord(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCompleteFiles(t *testing.T) {
	results := completeFiles("")
	if len(results) == 0 {
		t.Error("completeFiles('') should list current directory")
	}

	results = completeFiles("/")
	if len(results) == 0 {
		t.Error("completeFiles('/') should list root directory")
	}
}

func TestPrintPkgUsage(t *testing.T) {
	var buf bytes.Buffer
	printPkgUsage(&buf)

	output := buf.String()
	for _, cmd := range []string{"install", "remove", "burn", "diff", "inspect", "freeze", "list"} {
		if !strings.Contains(output, cmd) {
			t.Errorf("usage does not contain %q", cmd)
		}
	}
}

func TestCompleteCommands(t *testing.T) {
	results := completeCommands("ls")
	if len(results) == 0 {
		t.Error("completeCommands('ls') should return at least one match")
	}
}

func TestCompleteBuiltinCmds(t *testing.T) {
	results := completeBuiltinCmds("pk")
	if len(results) != 1 || results[0] != "pkg" {
		t.Errorf("completeBuiltinCmds('pk') = %v, want [pkg]", results)
	}

	empty := completeBuiltinCmds("zzz")
	if len(empty) != 0 {
		t.Errorf("completeBuiltinCmds('zzz') = %v, want []", empty)
	}
}

func TestCompletePkgSubcommands(t *testing.T) {
	results := completePkgSubcommands("in")
	if len(results) == 0 {
		t.Errorf("completePkgSubcommands('in') = %v, want at least install", results)
	}

	results = completePkgSubcommands("zzz")
	if len(results) != 0 {
		t.Errorf("completePkgSubcommands('zzz') = %v, want []", results)
	}
}

func TestCompletePermCategories(t *testing.T) {
	results := completePermCategories("net")
	if len(results) == 0 {
		t.Errorf("completePermCategories('net') = %v, want at least network", results)
	}
}

func TestIsExitError(t *testing.T) {
	if isExitError(nil) {
		t.Error("nil is not an exit error")
	}
}

func TestIsInterrupt(t *testing.T) {
	if isInterrupt(nil) {
		t.Error("nil is not an interrupt")
	}
	if !isInterrupt(fmt.Errorf("user interrupt signal")) {
		t.Error("error with 'interrupt' should be true")
	}
}

func TestEnvWithOverrides(t *testing.T) {
	env := envWithOverrides(
		expand.ListEnviron("PATH=/bin", "USH_PRELOAD_IDENTITY=host"),
		map[string]string{"USH_PRELOAD_IDENTITY": "root"},
	)

	joined := "\n" + strings.Join(env, "\n") + "\n"
	if !strings.Contains(joined, "\nPATH=/bin\n") {
		t.Fatalf("env missing PATH: %v", env)
	}
	if !strings.Contains(joined, "\nUSH_PRELOAD_IDENTITY=root\n") {
		t.Fatalf("env did not override preload identity: %v", env)
	}
	if strings.Contains(joined, "\nUSH_PRELOAD_IDENTITY=host\n") {
		t.Fatalf("env kept old preload identity: %v", env)
	}
}
