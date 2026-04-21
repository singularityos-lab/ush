// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package guardclient is the thin client the ush shell builtins (scan, guard,
// quarantine) use to talk to the Singularity Guard daemon (singd) over its
// control socket. One request, one JSON response, then close.
package guardclient

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/singularityos-lab/ush/internal/guardproto"
)

// ErrUnavailable is returned when singd is not reachable.
var ErrUnavailable = errors.New("singd not running")

// Available reports whether the guard control socket accepts connections.
func Available() bool {
	conn, err := net.DialTimeout("unix", guardproto.ControlSocket(), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Do sends a single command to singd and returns its response. If singd is not
// running it returns ErrUnavailable so callers can print a hint.
func Do(cmd string, args ...string) (guardproto.Response, error) {
	conn, err := net.DialTimeout("unix", guardproto.ControlSocket(), 500*time.Millisecond)
	if err != nil {
		return guardproto.Response{}, ErrUnavailable
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	req := guardproto.Request{Cmd: cmd, Args: args}
	data, err := json.Marshal(req)
	if err != nil {
		return guardproto.Response{}, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return guardproto.Response{}, err
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return guardproto.Response{}, err
	}

	var resp guardproto.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return guardproto.Response{}, err
	}
	return resp, nil
}

