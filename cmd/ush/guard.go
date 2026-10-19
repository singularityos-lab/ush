package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/singularityos-lab/ush/internal/broker"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/security"
)

const guardChildEnv = "USH_GUARD_CHILD"

func init() {
	if os.Getenv(guardChildEnv) != "1" {
		return
	}
	runtime.LockOSThread()
	os.Unsetenv(guardChildEnv)
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	if err := security.EnterDeleteGuard(3); err != nil {
		fmt.Fprintf(os.Stderr, "\033[1;31mush: the deletion guard could not start (%v); this shell is unprotected\033[0m\n", err)
	}
	path, err := exec.LookPath(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ush: %v\n", err)
		os.Exit(127)
	}
	err = syscall.Exec(path, os.Args[1:], os.Environ())
	fmt.Fprintf(os.Stderr, "ush: exec %s: %v\n", path, err)
	os.Exit(126)
}

// runGuard runs a program on the host under the deletion guard only: it is not
// sandboxed, but mass deletions in the user's files pause for confirmation and
// the home and personal folders cannot be removed.
func runGuard(args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ush --guard -- PROGRAM [ARGS...]")
		return 2
	}
	ushlog.Init("error", io.Discard)
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ush: %v\n", err)
		return 1
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ush: %v\n", err)
		return 1
	}
	childSock := os.NewFile(uintptr(pair[1]), "guard")
	cmd := exec.Command(self, args...)
	cmd.Env = append(os.Environ(), guardChildEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childSock}

	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
	forward := make(chan os.Signal, 4)
	signal.Notify(forward, syscall.SIGHUP, syscall.SIGTERM)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ush: %v\n", err)
		return 1
	}
	childSock.Close()
	child := cmd.Process.Pid

	if fd, err := security.ReceiveFd(pair[0]); err == nil {
		sup := security.NewSupervisor(fd, nil)
		if home, err := os.UserHomeDir(); err == nil {
			guard := security.NewDeleteGuard(home, nil)
			guard.SetShellPid(func() int { return child })
			guard.SetConfirm(func(app, where string, count int) bool {
				bc := guardBroker()
				if bc == nil {
					return false
				}
				ok, err := bc.ConfirmDelete(app, where)
				return err == nil && ok
			})
			sup.SetDeleteGuard(guard)
		}
		go sup.Run()
		defer sup.Stop()
	}
	unix.Close(pair[0])

	go func() {
		for sig := range forward {
			cmd.Process.Signal(sig)
		}
	}()
	err = cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

func guardBroker() *broker.Client {
	if !broker.IsAvailable() {
		startBrokerDirect()
		for i := 0; i < 20 && !broker.IsAvailable(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !broker.IsAvailable() {
		return nil
	}
	bc, err := broker.NewClient("host-shell")
	if err != nil {
		return nil
	}
	return bc
}
