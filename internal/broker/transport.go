// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// transport.go carries the broker RPC over a PRIVATE AF_UNIX socket using a
// newline-delimited JSON protocol (same shape as the singd control channel).
//
// A session-bus transport would force ush to bind-mount the whole host
// XDG_RUNTIME_DIR (including `bus`) into the guest. That bus also exposes
// org.freedesktop.systemd1, so a guest could call StartTransientUnit and have
// the host's `systemd --user` spawn a process OUTSIDE every namespace, as the
// host user -- bypassing namespaces, seccomp and Landlock through one open door.
//
// With a dedicated socket the guest never needs the host session bus: ush
// exposes only this socket (and specific GUI sockets) into the guest. The broker
// still uses D-Bus for one thing, talking outward to a desktop portal to render
// a dialog (host to host, in showDialog); the guest never touches that path.
package broker

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// SocketPath returns the path of the broker's private control socket. It lives
// under $XDG_RUNTIME_DIR/ush/, a directory ush bind-mounts into the guest on
// its own (never the whole runtime dir). Overridable via USH_BROKER_SOCK so a
// test harness can point both ends at the same path.
func SocketPath() string {
	if s := os.Getenv("USH_BROKER_SOCK"); s != "" {
		return s
	}
	rt := os.Getenv("XDG_RUNTIME_DIR")
	if rt == "" {
		rt = filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
	}
	return filepath.Join(rt, "ush", "broker.sock")
}

// rpcRequest is one guest-to-broker call. One request per connection.
type rpcRequest struct {
	Method    string `json:"method"`
	Category  string `json:"category,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Reason    string `json:"reason,omitempty"`
	SessionID string `json:"session,omitempty"`
	App       string `json:"app,omitempty"`
}

// rpcResponse is the broker's reply.
type rpcResponse struct {
	Decision    string `json:"decision,omitempty"`
	Trusted     bool   `json:"trusted,omitempty"`
	Permissions string `json:"permissions,omitempty"`
	Error       string `json:"error,omitempty"`
}

// writeMessage marshals v to JSON and writes it as a single newline-terminated
// frame.
func writeMessage(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}

// readMessage reads one newline-terminated JSON frame into v.
func readMessage(r *bufio.Reader, v interface{}) error {
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	return json.Unmarshal(line, v)
}

const dialDeadline = 12 * time.Second

// serve accepts connections on the control socket. Each connection carries one
// request and is handled in its own goroutine so a slow dialog for one request
// never blocks others (e.g. every connect() apt makes).
func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	var req rpcRequest
	if err := readMessage(r, &req); err != nil {
		return
	}
	resp := s.dispatch(req)
	_ = writeMessage(conn, resp)
}

// dispatch routes one RPC request to the matching handler.
func (s *Server) dispatch(req rpcRequest) rpcResponse {
	switch req.Method {
	case "RequestPermission":
		return rpcResponse{Decision: s.requestPermission(req.Category, req.Resource, req.Reason, req.SessionID)}
	case "RevokePermission":
		if err := s.revokePermission(req.Category, req.Resource); err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{}
	case "AllowApp":
		if err := s.allowApp(req.App); err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{}
	case "DenyApp":
		if err := s.denyApp(req.App); err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{}
	case "IsAppTrusted":
		return rpcResponse{Trusted: s.isAppTrusted(req.App)}
	case "TrustDir":
		if err := s.trustDir(req.Resource); err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{}
	case "UntrustDir":
		if err := s.untrustDir(req.Resource); err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{}
	case "ListDevDirs":
		return rpcResponse{Permissions: s.listDevDirs()}
	case "RequestDevShell":
		return rpcResponse{Trusted: s.requestDevShell()}
	case "ListPermissions":
		perms, err := s.listPermissions()
		if err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{Permissions: perms}
	default:
		return rpcResponse{Error: "unknown method: " + req.Method}
	}
}
