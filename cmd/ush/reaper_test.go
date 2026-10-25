// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const orphanScript = `
for i in 1 2 3 4 5 6 7 8 9 10; do sh -c 'sleep 0.05 & exit 0'; done
sleep 0.5
z=0
for f in /proc/[0-9]*/stat; do
	case "$(cat "$f" 2>/dev/null)" in *") Z "*) z=$((z+1)) ;; esac
done
echo "zombies=$z"
exit 7
`

func TestReaperHelper(t *testing.T) {
	if os.Getenv("USH_REAPER_HELPER") != "1" {
		t.Skip("helper")
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", orphanScript)
	cmd.Stdout = os.Stdout
	err := superviseChild(cmd)
	var ge guestExit
	if errors.As(err, &ge) {
		os.Exit(int(ge))
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorReapsOrphans(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestReaperHelper$")
	cmd.Env = append(os.Environ(), "USH_REAPER_HELPER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.Output()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Skipf("nested namespaces unavailable: %v", err)
	}
	if !strings.Contains(string(out), "zombies=0") {
		t.Fatalf("orphans left as zombies: %q", out)
	}
	if ee.ExitCode() != 7 {
		t.Fatalf("exit code = %d, want 7", ee.ExitCode())
	}
}

func TestGuestShellEnvMovesPreload(t *testing.T) {
	env := guestShellEnv([]string{"A=1", "LD_PRELOAD=/run/ush/exec/shim.so"})
	if strings.Join(env, " ") != "A=1 "+envGuestPreload+"=/run/ush/exec/shim.so" {
		t.Fatalf("env = %v", env)
	}
}
