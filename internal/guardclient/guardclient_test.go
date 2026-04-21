// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package guardclient

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/ush/internal/guardproto"
)

// fakeSingd starts a one-shot control server that runs handler for each request.
func fakeSingd(t *testing.T, sock string, handler func(guardproto.Request) guardproto.Response) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, _ := bufio.NewReader(conn).ReadBytes('\n')
				var req guardproto.Request
				_ = json.Unmarshal(line, &req)
				data, _ := json.Marshal(handler(req))
				_, _ = conn.Write(append(data, '\n'))
			}()
		}
	}()
}

func TestDoUnavailable(t *testing.T) {
	t.Setenv("USH_GUARD_CTL_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
	if _, err := Do("status"); err != ErrUnavailable {
		t.Errorf("want ErrUnavailable, got %v", err)
	}
	if Available() {
		t.Error("Available() should be false when singd is absent")
	}
}

func TestDoRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "c.sock")
	t.Setenv("USH_GUARD_CTL_SOCK", sock)

	reqCh := make(chan guardproto.Request, 1)
	fakeSingd(t, sock, func(r guardproto.Request) guardproto.Response {
		reqCh <- r
		return guardproto.Response{OK: true, Output: "clean"}
	})

	resp, err := Do("scan", "/home/x")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Output != "clean" {
		t.Errorf("response mismatch: %+v", resp)
	}
	got := <-reqCh
	if got.Cmd != "scan" || len(got.Args) != 1 || got.Args[0] != "/home/x" {
		t.Errorf("server received wrong request: %+v", got)
	}
	if !Available() {
		t.Error("Available() should be true when singd is listening")
	}
}
