// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKindOfGenericCalls(t *testing.T) {
	for nr, want := range map[int32]callKind{
		unix.SYS_EXECVE:   callExec,
		unix.SYS_OPENAT:   callOpenat,
		unix.SYS_OPENAT2:  callOpenat2,
		unix.SYS_UNLINKAT: callUnlinkat,
		unix.SYS_GETPID:   callOther,
	} {
		if got := kindOf(nr); got != want {
			t.Errorf("kindOf(%d) = %d, want %d", nr, got, want)
		}
	}
}

func TestCallsOfIsSortedAndComplete(t *testing.T) {
	nrs := callsOf(callUnlink, callUnlinkat, callRename, callRenameat)
	if len(nrs) != 3+len(legacyCalls)-countKind(callOpen, callCreat, callChmod) {
		t.Fatalf("callsOf returned %v", nrs)
	}
	for i := 1; i < len(nrs); i++ {
		if nrs[i-1] >= nrs[i] {
			t.Fatalf("callsOf not sorted: %v", nrs)
		}
	}
}

func countKind(kinds ...callKind) int {
	n := 0
	for _, k := range legacyCalls {
		for _, want := range kinds {
			if k == want {
				n++
			}
		}
	}
	return n
}

func TestFiltersCheckRunningArch(t *testing.T) {
	for name, f := range map[string][]unix.SockFilter{
		"block":  buildBlockFilter([]uint32{unix.SYS_PTRACE}),
		"notify": buildNotifyFilter([]uint32{unix.SYS_EXECVE}, nil),
		"jail":   buildJailFilter(false),
	} {
		if f[1].K != auditArch {
			t.Errorf("%s filter checks arch %#x, want %#x", name, f[1].K, auditArch)
		}
	}
}

func TestFiltersOnRunningKernel(t *testing.T) {
	if mode := os.Getenv("USH_SECCOMP_CHILD"); mode != "" {
		runFilterChild(mode)
		return
	}
	for _, mode := range []string{"block", "jail"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFiltersOnRunningKernel$")
		cmd.Env = append(os.Environ(), "USH_SECCOMP_CHILD="+mode)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "child: ok") {
			t.Errorf("%s filter on this kernel: %v\n%s", mode, err, out)
		}
	}
}

func runFilterChild(mode string) {
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Println("child: no_new_privs:", err)
		os.Exit(1)
	}
	var err error
	if mode == "jail" {
		err = InstallJailSeccomp(false)
	} else {
		err = InstallSeccompFilter()
	}
	if err != nil {
		fmt.Println("child: install:", err)
		os.Exit(1)
	}
	if _, _, errno := unix.Syscall(unix.SYS_PTRACE, unix.PTRACE_PEEKUSR, 0, 0); errno != unix.EPERM {
		fmt.Println("child: ptrace not refused:", errno)
		os.Exit(1)
	}
	if mode == "jail" {
		if _, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); err != unix.EPERM {
			fmt.Println("child: inet socket not refused:", err)
			os.Exit(1)
		}
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Println("child: unix socket refused:", err)
			os.Exit(1)
		}
		unix.Close(fd)
	}
	if unix.Getpid() <= 0 {
		os.Exit(1)
	}
	fmt.Println("child: ok")
	os.Exit(0)
}
