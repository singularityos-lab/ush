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
	Enable    bool   `json:"enable,omitempty"`
	// Origin says where the request started (see origin.go). Absent means the
	// local control socket, which is what every pre-existing client sends.
	Origin string `json:"origin,omitempty"`
	// PIN is carried only by SetBootloaderUnlockArmed when arming. It is passed
	// to sinty-recoverd for verification and is never logged or stored.
	PIN string `json:"pin,omitempty"`
	// Action and Detail carry an SdbElevate call: Action is the kind of privilege
	// the bridge is asking for (shell-root, write-system, bind-privileged-port)
	// and Detail is its argument (the target path, the port), empty for a plain
	// root shell. The path in Detail is already confined by sdbd; the broker only
	// mediates the privilege on it.
	Action string `json:"action,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// rpcResponse is the broker's reply.
type rpcResponse struct {
	Decision    string `json:"decision,omitempty"`
	Trusted     bool   `json:"trusted,omitempty"`
	Permissions string `json:"permissions,omitempty"`
	Error       string `json:"error,omitempty"`
	Policy      string `json:"policy,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`

	// OK / Message and the lock fields answer the bootloader methods. OK is
	// false whenever Error is set, so a client that only reads OK still fails
	// closed.
	OK          bool   `json:"ok,omitempty"`
	Message     string `json:"message,omitempty"`
	Locked      bool   `json:"locked,omitempty"`
	UnlockArmed bool   `json:"unlock_armed,omitempty"`
	UnlockCount int    `json:"unlock_count,omitempty"`
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

// permissionReadDeadline bounds the read of an interactive permission reply. The
// broker only answers after the user acts on the dialog, so the wait must cover
// human response time (reading the prompt, deciding, clicking) plus first-boot
// dialog-render latency -- the short dialDeadline used for dial/write would time
// the read out mid-dialog and surface as a spurious "network access denied".
const permissionReadDeadline = 5 * time.Minute

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
	resp := s.dispatchFrom(req, peerFromConn(conn))
	_ = writeMessage(conn, resp)
}

// dispatch routes one RPC request with no peer credentials attached. The
// operations that need to know who is calling refuse an unknown peer, so this
// entry point stays usable for everything that does not.
func (s *Server) dispatch(req rpcRequest) rpcResponse {
	return s.dispatchFrom(req, peerIdentity{})
}

// dispatchFrom routes one RPC request from a peer whose credentials the kernel
// reported (see peer.go).
func (s *Server) dispatchFrom(req rpcRequest, peer peerIdentity) rpcResponse {
	switch req.Method {
	case "RequestPermission":
		return rpcResponse{Decision: s.requestPermissionFrom(
			req.Category, req.Resource, req.Reason, req.SessionID, parseOrigin(req.Origin))}
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
	case "DevShellStatus":
		// The broker owns the host-side storage dir, so a guest-side `dsh status`
		// reports the real opt-in state instead of the sandbox's ephemeral copy.
		pol, enabled := s.devShellStatus()
		return rpcResponse{Policy: pol, Enabled: enabled}
	case "SetDevShellEnabled":
		// Same reason: route the CLI toggle through the broker so the marker lands
		// in host storage, where the dsh gate actually reads it.
		if err := s.setDevShellEnabled(req.Enable); err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{}
	case "BootloaderLockState":
		st, err := s.bootloaderLockState()
		if err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{
			OK:          true,
			Locked:      st.Locked,
			UnlockArmed: st.UnlockArmed,
			UnlockCount: st.UnlockCount,
		}
	case "SetBootloaderUnlockArmed":
		reply, err := s.setBootloaderUnlockArmed(req.Enable, req.PIN, parseOrigin(req.Origin), peer)
		if err != nil {
			return rpcResponse{Error: err.Error(), Message: reply.Message}
		}
		return rpcResponse{OK: true, Message: reply.Message}
	case "ListPermissions":
		perms, err := s.listPermissions()
		if err != nil {
			return rpcResponse{Error: err.Error()}
		}
		return rpcResponse{Permissions: perms}
	case "SdbElevate":
		granted, reason := s.sdbElevate(req.Action, req.Detail, req.SessionID, parseOrigin(req.Origin))
		return rpcResponse{OK: granted, Message: reason}
	default:
		return rpcResponse{Error: "unknown method: " + req.Method}
	}
}
