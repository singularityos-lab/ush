package broker

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCpakOperations(t *testing.T) {
	for _, args := range [][]string{
		{"doctor"}, {"list"}, {"install", "https://github.com/Containerpak/bottles"},
		{"install", "--flatpak", "com.usebottles.bottles"}, {"run", "bottles"},
		{"update", "bottles"}, {"remove", "bottles"},
	} {
		r, err := ParseCpakRequest(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		got, err := CpakArguments(r)
		want := args
		if args[0] == "update" {
			want = append(append([]string{}, args...), "--non-interactive")
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%v: %v, %v", args, got, err)
		}
	}
	for _, args := range [][]string{
		nil, {"shell", "bottles"}, {"run", "bottles", "/bin/sh"}, {"run", "--env=LD_PRELOAD=x"},
		{"install", "/home/user/file"}, {"install", "https://evil.test/app"},
		{"install", "https://github.com/a/b?x=y"}, {"install", "https://github.com/a/../b"},
		{"install", "https://github.com/a/%62"}, {"install", "--flatpak", "/etc/passwd"},
		{"remove", "bottles", "--purge"}, {"update"}, {"doctor", "--json"},
		{"run", "a\nb"}, {"run", "a;id"}, {"run", "../b"}, {"run", "-b"},
	} {
		if _, err := ParseCpakRequest(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestCpakOwnerAndConsent(t *testing.T) {
	s := &Server{auto: &autoDecider{enabled: true, confirm: true}}
	req := rpcRequest{Method: "Cpak", Cpak: &CpakRequest{Operation: "doctor"}}
	for _, peer := range []peerIdentity{{}, {known: true, uid: uint32(os.Getuid()) + 1}} {
		if _, err := s.authorizeCpak(req, peer); err == nil {
			t.Fatal("accepted untrusted peer")
		}
	}
	owner := peerIdentity{known: true, uid: uint32(os.Getuid())}
	req.Origin = "sdb:remote"
	if _, err := s.authorizeCpak(req, owner); err == nil {
		t.Fatal("accepted remote request")
	}
	req.Origin = ""
	s.auto.confirm = false
	if _, err := s.authorizeCpak(req, owner); err == nil {
		t.Fatal("ignored denial")
	}
	s.auto.confirm = true
	if _, err := s.authorizeCpak(req, owner); err != nil {
		t.Fatal(err)
	}
}

func TestCpakHostEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LD_PRELOAD", "/guest/evil.so")
	t.Setenv("CPAK_HOME", "/guest/store")
	t.Setenv("GIT_SSH_COMMAND", "/guest/ssh")
	cmd := cpakCommand(context.Background(), []string{"doctor"})
	if cmd.Path != "/usr/bin/cpak" {
		t.Fatal(cmd.Path)
	}
	if cmd.Dir != home {
		t.Fatalf("working directory %q, want host home %q", cmd.Dir, home)
	}
	foundHome := false
	for _, value := range cmd.Env {
		if value == "HOME="+home {
			foundHome = true
		}
		if strings.HasPrefix(value, "LD_") || strings.HasPrefix(value, "CPAK_") || strings.HasPrefix(value, "GIT_") {
			t.Fatal(value)
		}
	}
	if !foundHome {
		t.Fatal("host home missing from command environment")
	}
}

func cpakTestServer(t *testing.T, command func(context.Context, []string) *exec.Cmd) *Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cpak.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{auto: &autoDecider{enabled: true, confirm: true}}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req rpcRequest
		if readMessage(bufio.NewReader(conn), &req) != nil {
			return
		}
		s.serveCpakCommand(conn, req, peerFromConn(conn), command)
	}()
	return &Client{socket: path}
}

func TestCpakStdioAndExit(t *testing.T) {
	c := cpakTestServer(t, func(ctx context.Context, args []string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "read line; printf 'out:%s' \"$line\"; printf err >&2; exit 7")
	})
	in, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	w.WriteString("hello\n")
	w.Close()
	var out, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code, err := c.RunCpak(ctx, CpakRequest{Operation: "doctor"}, in, &out, &stderr)
	if err != nil || code != 7 || out.String() != "out:hello" || stderr.String() != "err" {
		t.Fatalf("code=%d err=%v stdout=%q stderr=%q", code, err, out.String(), stderr.String())
	}
}

func TestCpakRejectsRegularDescriptors(t *testing.T) {
	c := cpakTestServer(t, func(ctx context.Context, args []string) *exec.Cmd {
		t.Error("command started with regular descriptors")
		return exec.CommandContext(ctx, "/bin/true")
	})
	f, err := os.Create(filepath.Join(t.TempDir(), "input"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.RunCpak(ctx, CpakRequest{Operation: "doctor"}, f, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "descriptors") {
		t.Fatal(err)
	}
}

func TestCpakRejectsMissingDescriptors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fds.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err = client.WriteMsgUnix([]byte{0}, unix.UnixRights(int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err = receiveCpakFiles(server); err == nil {
		t.Fatal("accepted one descriptor")
	}
}

func TestCpakDisconnectCancelsHostCommand(t *testing.T) {
	client := cpakTestServer(t, func(ctx context.Context, args []string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "30")
	})
	input, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = client.RunCpak(ctx, CpakRequest{Operation: "doctor"}, input, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("cancelled command succeeded")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("host command did not stop on disconnect")
	}
}
