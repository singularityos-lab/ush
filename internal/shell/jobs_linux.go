// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

//go:build linux

package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"mvdan.cc/sh/v3/interp"
)

type jobState int

const (
	jobRunning jobState = iota
	jobStopped
	jobDone
)

type job struct {
	id      int
	pgid    int
	cmd     string
	state   jobState
	code    uint8
	signal  syscall.Signal
	modes   *unix.Termios
	notify  bool
	proc    *os.Process
	changed chan struct{}
}

type jobTable struct {
	mu   sync.Mutex
	list []*job
}

var errInterrupted = errors.New("interrupted")

var jobBuiltins = map[string]string{"fg": "ush:fg", "bg": "ush:bg", "jobs": "ush:jobs"}

func jobCallHandler(ctx context.Context, args []string) ([]string, error) {
	if name, ok := jobBuiltins[args[0]]; ok {
		return append([]string{name}, args[1:]...), nil
	}
	return args, nil
}

func fileFd(v any) int {
	f, ok := v.(*os.File)
	if !ok {
		return -1
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return -1
	}
	fd := -1
	rc.Control(func(p uintptr) { fd = int(p) })
	return fd
}

func isTerminal(fd int) bool {
	if fd < 0 {
		return false
	}
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

func (sh *Shell) foregroundTerminal(hc interp.HandlerContext) (int, bool) {
	if !sh.interactive {
		return -1, false
	}
	in, out := fileFd(hc.Stdin), fileFd(hc.Stdout)
	if fileFd(hc.Stderr) < 0 || !isTerminal(in) || !isTerminal(out) {
		return -1, false
	}
	pgrp, err := unix.IoctlGetInt(in, unix.TIOCGPGRP)
	if err != nil || pgrp != unix.Getpgrp() {
		return -1, false
	}
	return in, true
}

func setForeground(fd, pgid int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var block, old unix.Sigset_t
	block.Val[0] = 1 << (uint(unix.SIGTTOU) - 1)
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &block, &old); err != nil {
		return err
	}
	err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgid)
	unix.PthreadSigmask(unix.SIG_SETMASK, &old, nil)
	return err
}

func (sh *Shell) runForeground(ctx context.Context, args []string) (bool, error) {
	hc := interp.HandlerCtx(ctx)
	fd, ok := sh.foregroundTerminal(hc)
	if !ok {
		return false, nil
	}
	path, err := interp.LookPathDir(hc.Dir, hc.Env, args[0])
	if err != nil {
		fmt.Fprintln(hc.Stderr, err)
		return true, interp.NewExitStatus(127)
	}
	cmd := exec.Command(path)
	cmd.Args = args
	cmd.Dir = hc.Dir
	cmd.Env = envWithOverrides(hc.Env, nil)
	cmd.Stdin = hc.Stdin.(*os.File)
	cmd.Stdout = hc.Stdout.(*os.File)
	cmd.Stderr = hc.Stderr.(*os.File)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
	modes, _ := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(hc.Stderr, err)
		if errors.Is(err, os.ErrPermission) {
			return true, interp.NewExitStatus(126)
		}
		return true, interp.NewExitStatus(127)
	}
	j := sh.jobs.add(cmd.Process, strings.Join(args, " "))
	return true, sh.waitForeground(hc.Stderr, fd, j, modes)
}

func (t *jobTable) add(proc *os.Process, cmd string) *job {
	t.mu.Lock()
	id := 1
	for _, j := range t.list {
		if j.id >= id {
			id = j.id + 1
		}
	}
	j := &job{id: id, pgid: proc.Pid, cmd: cmd, proc: proc, changed: make(chan struct{}, 1)}
	t.list = append(t.list, j)
	t.mu.Unlock()
	go t.watch(j)
	return j
}

func (t *jobTable) watch(j *job) {
	for {
		var ws unix.WaitStatus
		_, err := unix.Wait4(j.proc.Pid, &ws, unix.WUNTRACED|unix.WCONTINUED, nil)
		if err == unix.EINTR {
			continue
		}
		t.mu.Lock()
		finished := true
		switch {
		case err != nil:
			j.state, j.code = jobDone, 127
		case ws.Exited():
			j.state, j.code = jobDone, uint8(ws.ExitStatus())
		case ws.Signaled():
			j.state, j.signal = jobDone, ws.Signal()
			j.code = uint8(128 + int(ws.Signal()))
		case ws.Stopped():
			j.state, finished = jobStopped, false
		case ws.Continued():
			j.state, finished = jobRunning, false
		default:
			finished = false
		}
		t.mu.Unlock()
		select {
		case j.changed <- struct{}{}:
		default:
		}
		if finished {
			j.proc.Release()
			return
		}
	}
}

func (t *jobTable) state(j *job) jobState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return j.state
}

func (t *jobTable) remove(j *job) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, x := range t.list {
		if x == j {
			t.list = append(t.list[:i], t.list[i+1:]...)
			return
		}
	}
}

func (sh *Shell) waitForeground(stderr io.Writer, fd int, j *job, modes *unix.Termios) error {
	for sh.jobs.state(j) == jobRunning {
		<-j.changed
	}
	setForeground(fd, unix.Getpgrp())
	if sh.jobs.state(j) == jobStopped {
		j.modes, _ = unix.IoctlGetTermios(fd, unix.TCGETS)
		if modes != nil {
			unix.IoctlSetTermios(fd, unix.TCSETSW, modes)
		}
		sh.jobs.mu.Lock()
		j.notify = true
		sh.jobs.mu.Unlock()
		fmt.Fprintf(stderr, "\n[%d]+  Stopped                 %s\n", j.id, j.cmd)
		return interp.NewExitStatus(148)
	}
	sh.jobs.remove(j)
	if j.signal != 0 && modes != nil {
		unix.IoctlSetTermios(fd, unix.TCSETSW, modes)
	}
	if j.signal == unix.SIGINT || j.signal == unix.SIGQUIT {
		fmt.Fprintln(stderr)
		return errInterrupted
	}
	if j.code != 0 {
		return interp.NewExitStatus(j.code)
	}
	return nil
}

func (t *jobTable) find(spec string) (*job, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var live []*job
	for _, j := range t.list {
		if j.state != jobDone {
			live = append(live, j)
		}
	}
	if len(live) == 0 {
		return nil, errors.New("no current job")
	}
	if spec == "" || spec == "%" || spec == "%%" || spec == "%+" {
		return live[len(live)-1], nil
	}
	if spec == "%-" {
		if len(live) < 2 {
			return nil, errors.New("no previous job")
		}
		return live[len(live)-2], nil
	}
	n, err := strconv.Atoi(strings.TrimPrefix(spec, "%"))
	if err == nil {
		for _, j := range live {
			if j.id == n {
				return j, nil
			}
		}
	} else {
		for i := len(live) - 1; i >= 0; i-- {
			if strings.HasPrefix(live[i].cmd, strings.TrimPrefix(spec, "%")) {
				return live[i], nil
			}
		}
	}
	return nil, fmt.Errorf("%s: no such job", spec)
}

func stateLabel(s jobState) string {
	switch s {
	case jobStopped:
		return "Stopped"
	case jobDone:
		return "Done"
	}
	return "Running"
}

func (sh *Shell) builtinJob(ctx context.Context, name string, args []string) error {
	hc := interp.HandlerCtx(ctx)
	switch name {
	case "jobs":
		sh.jobs.mu.Lock()
		for i, j := range sh.jobs.list {
			mark := " "
			if i == len(sh.jobs.list)-1 {
				mark = "+"
			} else if i == len(sh.jobs.list)-2 {
				mark = "-"
			}
			fmt.Fprintf(hc.Stdout, "[%d]%s  %-22s  %s\n", j.id, mark, stateLabel(j.state), j.cmd)
		}
		sh.jobs.mu.Unlock()
		return nil
	case "bg":
		spec := ""
		if len(args) > 0 {
			spec = args[0]
		}
		j, err := sh.jobs.find(spec)
		if err != nil {
			fmt.Fprintf(hc.Stderr, "bg: %v\n", err)
			return interp.NewExitStatus(1)
		}
		sh.jobs.mu.Lock()
		j.notify = true
		sh.jobs.mu.Unlock()
		unix.Kill(-j.pgid, unix.SIGCONT)
		fmt.Fprintf(hc.Stdout, "[%d]+ %s &\n", j.id, j.cmd)
		return nil
	}
	spec := ""
	if len(args) > 0 {
		spec = args[0]
	}
	fd, ok := sh.foregroundTerminal(hc)
	if !ok {
		fmt.Fprintln(hc.Stderr, "fg: no job control")
		return interp.NewExitStatus(1)
	}
	j, err := sh.jobs.find(spec)
	if err != nil {
		fmt.Fprintf(hc.Stderr, "fg: %v\n", err)
		return interp.NewExitStatus(1)
	}
	fmt.Fprintln(hc.Stdout, j.cmd)
	modes, _ := unix.IoctlGetTermios(fd, unix.TCGETS)
	if j.modes != nil {
		unix.IoctlSetTermios(fd, unix.TCSETSW, j.modes)
	}
	if err := setForeground(fd, j.pgid); err != nil {
		fmt.Fprintf(hc.Stderr, "fg: %v\n", err)
		return interp.NewExitStatus(1)
	}
	sh.jobs.mu.Lock()
	j.notify = false
	if j.state == jobStopped {
		j.state = jobRunning
	}
	sh.jobs.mu.Unlock()
	unix.Kill(-j.pgid, unix.SIGCONT)
	return sh.waitForeground(hc.Stderr, fd, j, modes)
}

func (t *jobTable) report(w io.Writer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.list[:0]
	for _, j := range t.list {
		if j.state == jobDone {
			if j.notify {
				fmt.Fprintf(w, "[%d]+  %-22s  %s\n", j.id, "Done", j.cmd)
			}
			continue
		}
		kept = append(kept, j)
	}
	t.list = kept
}
