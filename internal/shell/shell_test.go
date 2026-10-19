// SPDX-License-Identifier: GPL-3.0-or-later

package shell

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
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
	results := completeFiles("", "")
	if len(results) == 0 {
		t.Error("completeFiles('') should list current directory")
	}

	results = completeFiles("/", "")
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

func TestAfterLine(t *testing.T) {
	cases := []struct {
		line   string
		exit   bool
		report bool
	}{
		{"true", false, false},
		{"false", false, false},
		{"echo abc | grep -q zzz", false, false},
		{"exit 3", true, false},
		{"exit", true, false},
		{"echo 'unterminated", false, true},
	}
	for _, c := range cases {
		var out bytes.Buffer
		sh, err := New(&Config{StorageDir: t.TempDir(), Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out})
		if err != nil {
			t.Fatal(err)
		}
		exit, report := sh.afterLine(sh.RunLine(context.Background(), c.line))
		if exit != c.exit || (report != nil) != c.report {
			t.Errorf("%q: exit %v report %v, want exit %v report %v", c.line, exit, report, c.exit, c.report)
		}
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

func TestCompleteFilesUsesShellDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "trama"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trace.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tracked"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := completeFiles("tra", dir)
	sort.Strings(got)
	if want := []string{"trace.txt", "trama/"}; !reflect.DeepEqual(got, want) {
		t.Errorf("completeFiles(tra) = %v, want %v", got, want)
	}
	if got := completeFiles("sub/tr", dir); got != nil {
		t.Errorf("completeFiles(sub/tr) = %v, want nil", got)
	}
}

func TestRuneWidth(t *testing.T) {
	if got := visibleLen("\x1b[1;32mmirko\x1b[0m@\U0001F527DSH:"); got != 12 {
		t.Errorf("visibleLen = %d, want 12", got)
	}
}

func TestBuiltinErrorDoesNotEndShell(t *testing.T) {
	sh := &Shell{}
	var out, errOut bytes.Buffer
	failing := func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if args[0] == "boom" {
				return fmt.Errorf("broken install")
			}
			return next(ctx, args)
		}
	}
	runner, err := interp.New(interp.StdIO(nil, &out, &errOut), interp.ExecHandlers(sh.execHandler, failing))
	if err != nil {
		t.Fatal(err)
	}
	f, err := syntax.NewParser().Parse(strings.NewReader("boom; echo after $?"), "")
	if err != nil {
		t.Fatal(err)
	}
	runner.Run(context.Background(), f)
	if runner.Exited() {
		t.Fatal("a failing command ended the shell")
	}
	if !strings.Contains(out.String(), "after 1") {
		t.Errorf("stdout = %q, want the next command to run with status 1", out.String())
	}
	if !strings.Contains(errOut.String(), "broken install") {
		t.Errorf("stderr = %q, want the error message", errOut.String())
	}
}
