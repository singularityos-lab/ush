package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if os.Getenv("USH_DELGUARD_CHILD") == "" {
		return
	}
	runtime.LockOSThread()
	if err := EnterDeleteGuard(3); err != nil {
		fmt.Println("enter:", err)
		os.Exit(3)
	}
	home := os.Getenv("USH_DELGUARD_CHILD")
	if script := os.Getenv("USH_DELGUARD_EXEC"); script != "" {
		os.Chdir(home)
		err := syscall.Exec("/bin/sh", []string{"sh", "-c", script}, os.Environ())
		fmt.Println("exec:", err)
		os.Exit(4)
	}
	report := func(name string, err error) {
		if err == nil {
			fmt.Printf("%s=ok\n", name)
			return
		}
		if pe, ok := err.(*os.PathError); ok {
			err = pe.Err
		}
		if le, ok := err.(*os.LinkError); ok {
			err = le.Err
		}
		fmt.Printf("%s=%v\n", name, err)
	}
	report("rmdir-documents", syscall.Rmdir(filepath.Join(home, "Documents")))
	report("rename-pictures", os.Rename(filepath.Join(home, "Pictures"), filepath.Join(home, "elsewhere")))
	for _, dir := range strings.Split(os.Getenv("USH_DELGUARD_DIRS"), ",") {
		n := 0
		ents, _ := os.ReadDir(filepath.Join(home, dir))
		for _, e := range ents {
			if err := syscall.Unlink(filepath.Join(home, dir, e.Name())); err == nil {
				n++
			} else {
				fmt.Printf("unlink-%s=%v\n", dir, err)
				break
			}
		}
		fmt.Printf("deleted-%s=%d\n", dir, n)
	}
	os.Exit(0)
}

var childIsShell bool

type guardRun struct {
	out    string
	err    error
	asked  int32
	remain map[string]int
}

func runGuarded(t *testing.T, allow bool, dirs map[string]int, script ...string) guardRun {
	t.Helper()
	home := t.TempDir()
	for _, d := range []string{"Documents/keep", "Pictures"} {
		os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	os.WriteFile(filepath.Join(home, "Documents", "keep", "f"), nil, 0o644)
	var order []string
	for d, n := range dirs {
		order = append(order, d)
		os.MkdirAll(filepath.Join(home, d), 0o755)
		for i := 0; i < n; i++ {
			os.WriteFile(filepath.Join(home, d, fmt.Sprintf("f%03d", i)), nil, 0o644)
		}
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	child := os.NewFile(uintptr(pair[1]), "child")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "USH_DELGUARD_CHILD="+home, "USH_DELGUARD_DIRS="+strings.Join(order, ","))
	if len(script) > 0 {
		cmd.Env = append(cmd.Env, "USH_DELGUARD_EXEC="+script[0])
	}
	cmd.ExtraFiles = []*os.File{child}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()
	fd, err := ReceiveFd(pair[0])
	unix.Close(pair[0])
	if err != nil {
		cmd.Process.Kill()
		t.Fatal(err)
	}

	var r guardRun
	g := NewDeleteGuard(home, nil)
	g.SetLimit(20, time.Minute)
	g.SetConfirm(func(cmd, where string, count int) bool {
		atomic.AddInt32(&r.asked, 1)
		if where != "~/Documents" && where != "~/Music" {
			t.Errorf("dialog location = %q", where)
		}
		return allow
	})
	if childIsShell {
		pid := cmd.Process.Pid
		g.SetShellPid(func() int { return pid })
	}
	sup := NewSupervisor(fd, nil)
	sup.SetDeleteGuard(g)
	go sup.Run()
	defer sup.Stop()

	r.err = cmd.Wait()
	r.out = out.String()
	r.remain = map[string]int{}
	for d := range dirs {
		ents, _ := os.ReadDir(filepath.Join(home, d))
		r.remain[d] = len(ents)
	}
	return r
}

func TestDeleteGuardProtectsPersonalFolders(t *testing.T) {
	r := runGuarded(t, true, nil)
	if !strings.Contains(r.out, "rmdir-documents=operation not permitted") {
		t.Errorf("rmdir of ~/Documents not refused:\n%s", r.out)
	}
	if !strings.Contains(r.out, "rename-pictures=operation not permitted") {
		t.Errorf("rename of ~/Pictures not refused:\n%s", r.out)
	}
}

func TestDeleteGuardStopsMassDeletion(t *testing.T) {
	r := runGuarded(t, false, map[string]int{"Documents/photos": 50})
	if r.asked != 1 {
		t.Fatalf("asked %d times, want 1\n%s", r.asked, r.out)
	}
	ee, ok := r.err.(*exec.ExitError)
	if !ok || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("deleting program not killed: %v\n%s", r.err, r.out)
	}
	if r.remain["Documents/photos"] != 30 {
		t.Fatalf("%d files left, want 30 (20 allowed before the guard)", r.remain["Documents/photos"])
	}
}

func TestDeleteGuardAllowsWhenConfirmed(t *testing.T) {
	r := runGuarded(t, true, map[string]int{"Music": 50})
	if r.err != nil || r.asked != 1 || r.remain["Music"] != 0 {
		t.Fatalf("err=%v asked=%d left=%d\n%s", r.err, r.asked, r.remain["Music"], r.out)
	}
}

func TestDeleteGuardIgnoresBuildDirs(t *testing.T) {
	r := runGuarded(t, false, map[string]int{"src/build": 60, ".cache/thumbs": 60})
	if r.err != nil || r.asked != 0 || r.remain["src/build"] != 0 || r.remain[".cache/thumbs"] != 0 {
		t.Fatalf("err=%v asked=%d left=%v\n%s", r.err, r.asked, r.remain, r.out)
	}
}

func TestDeleteGuardStopsRealRm(t *testing.T) {
	for _, tc := range []struct{ name, script string }{
		{"rm -rf", "rm -rf Documents/photos"},
		{"one rm per file", "for f in Documents/photos/*; do rm \"$f\"; done"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runGuarded(t, false, map[string]int{"Documents/photos": 50}, tc.script)
			if r.asked != 1 {
				t.Fatalf("asked %d times, want 1\n%s", r.asked, r.out)
			}
			if _, ok := r.err.(*exec.ExitError); !ok {
				t.Fatalf("script not stopped: %v\n%s", r.err, r.out)
			}
			if left := r.remain["Documents/photos"]; left < 29 || left > 30 {
				t.Fatalf("%d files left, want about 30\n%s", left, r.out)
			}
		})
	}
}

func TestDeleteGuardAsksAgainAfterBlock(t *testing.T) {
	childIsShell = true
	defer func() { childIsShell = false }()
	r := runGuarded(t, false, map[string]int{"Documents/photos": 50}, "rm -rf Documents/photos; rm -rf Documents/photos")
	if r.asked != 2 {
		t.Fatalf("asked %d times, want 2 (once per command)\n%s", r.asked, r.out)
	}
	if left := r.remain["Documents/photos"]; left < 29 {
		t.Fatalf("%d files left: the second command deleted more after the block\n%s", left, r.out)
	}
}
