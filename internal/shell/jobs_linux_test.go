// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package shell

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestJobControlHelper(t *testing.T) {
	if os.Getenv("USH_JOB_HELPER") != "1" {
		t.Skip("helper")
	}
	sh, err := New(&Config{StorageDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	sh.RunInteractive(context.Background())
}

type ptyLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *ptyLog) wait(t *testing.T, want string, from int) int {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		s := l.buf.String()
		l.mu.Unlock()
		if i := strings.Index(s[from:], want); i >= 0 {
			return from + i + len(want)
		}
		time.Sleep(20 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Fatalf("timed out waiting for %q in %q", want, l.buf.String()[from:])
	return 0
}

func TestJobControlOnPty(t *testing.T) {
	master, slave := openPty(t)
	defer master.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestJobControlHelper$")
	cmd.Env = append(os.Environ(), "USH_JOB_HELPER=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	defer cmd.Process.Kill()
	log := &ptyLog{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			if n > 0 {
				log.mu.Lock()
				log.buf.Write(b[:n])
				log.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	send := func(s string) {
		if _, err := master.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	pos := log.wait(t, "USH", 0)
	send("sleep 30\r")
	time.Sleep(300 * time.Millisecond)
	send("\x1a")
	pos = log.wait(t, "Stopped", pos)
	pos = log.wait(t, "sleep 30", pos)
	send("jobs\r")
	pos = log.wait(t, "[1]+  Stopped", pos)
	send("fg\r")
	pos = log.wait(t, "sleep 30", pos)
	time.Sleep(300 * time.Millisecond)
	send("\x03")
	pos = log.wait(t, "USH", pos)
	send("jobs; echo none-left\r")
	end := log.wait(t, "none-left\r\n", pos)
	log.mu.Lock()
	out := log.buf.String()[pos:end]
	log.mu.Unlock()
	if strings.Contains(out, "[1]") {
		t.Fatalf("job still listed after fg and interrupt: %q", out)
	}
	send("sleep 1\r")
	time.Sleep(300 * time.Millisecond)
	send("\x1a")
	pos = log.wait(t, "Stopped", pos)
	send("bg\r")
	pos = log.wait(t, "sleep 1 &", pos)
	time.Sleep(1500 * time.Millisecond)
	send("\r")
	pos = log.wait(t, "Done", pos)
	send("for i in 1 2 3; do sleep 5; done; echo after-loop\r")
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	send("\x03")
	send("echo loop-marker\r")
	end = log.wait(t, "loop-marker\r\n", pos)
	end = log.wait(t, "loop-marker\r\n", end)
	if time.Since(start) > 3*time.Second {
		t.Fatalf("interrupt did not stop the loop")
	}
	log.mu.Lock()
	out = log.buf.String()[pos:end]
	log.mu.Unlock()
	if strings.Count(out, "after-loop") > 1 {
		t.Fatalf("loop went on after the interrupt: %q", out)
	}
	pos = end
	send("sleep 30 &\r")
	time.Sleep(200 * time.Millisecond)
	send("echo still-reading\r")
	pos = log.wait(t, "still-reading\r\n", pos)
	send("exit\r")
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shell did not exit")
	}
}
