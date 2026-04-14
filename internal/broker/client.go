// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// broker/client.go implements the broker client used in the guest (and by the
// host-side seccomp supervisor). It talks to the broker over a PRIVATE AF_UNIX
// socket (see transport.go), NOT the host session bus, so the guest never needs
// access to that bus. One request per connection.
package broker

import (
	"bufio"
	"fmt"
	"net"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// Decision is the broker's decision.
type Decision string

const (
	DecisionAllow        Decision = "allow"
	DecisionAllowSession Decision = "allow_session"
	DecisionAllowAlways  Decision = "allow_always"
	DecisionDeny         Decision = "deny"
)

// Client is the broker client. It is stateless beyond the session id and the
// socket path; each call opens a short-lived connection.
type Client struct {
	socket    string
	sessionID string
}

// NewClient creates a new broker client pointed at the private control socket.
func NewClient(sessionID string) (*Client, error) {
	return &Client{
		socket:    SocketPath(),
		sessionID: sessionID,
	}, nil
}

// Close is a no-op (connections are per-call); kept for API compatibility.
func (c *Client) Close() {}

// call sends one request and returns the response.
func (c *Client) call(req rpcRequest) (rpcResponse, error) {
	conn, err := net.DialTimeout("unix", c.socket, dialDeadline)
	if err != nil {
		return rpcResponse{}, fmt.Errorf("broker: dial %s: %w", c.socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialDeadline))

	if err := writeMessage(conn, req); err != nil {
		return rpcResponse{}, err
	}
	var resp rpcResponse
	if err := readMessage(bufio.NewReader(conn), &resp); err != nil {
		return rpcResponse{}, err
	}
	return resp, nil
}

// RequestPermission requests a permission from the broker.
func (c *Client) RequestPermission(category, resource, reason string) (Decision, error) {
	resp, err := c.call(rpcRequest{
		Method:    "RequestPermission",
		Category:  category,
		Resource:  resource,
		Reason:    reason,
		SessionID: c.sessionID,
	})
	if err != nil {
		ushlog.Warn("broker client: permission request failed", "err", err)
		return DecisionDeny, fmt.Errorf("broker: %w", err)
	}
	ushlog.Debug("broker client: decision received",
		"category", category, "resource", resource, "decision", resp.Decision)
	return Decision(resp.Decision), nil
}

// IsAllowed checks whether a category/resource is permitted.
func (c *Client) IsAllowed(category, resource, reason string) bool {
	d, err := c.RequestPermission(category, resource, reason)
	if err != nil {
		return false
	}
	return d != DecisionDeny
}

// AllowApp grants blanket permission for an application (keyed on exe path).
func (c *Client) AllowApp(appExe string) error {
	resp, err := c.call(rpcRequest{Method: "AllowApp", App: appExe})
	if err != nil {
		return fmt.Errorf("broker: allow app: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("broker: %s", resp.Error)
	}
	return nil
}

// DenyApp removes blanket permission for an application.
func (c *Client) DenyApp(appExe string) error {
	resp, err := c.call(rpcRequest{Method: "DenyApp", App: appExe})
	if err != nil {
		return fmt.Errorf("broker: deny app: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("broker: %s", resp.Error)
	}
	return nil
}

// TrustDir grants a directory full host access from the guest (executables and
// VCS hooks run on the host). Requires host-side confirmation.
func (c *Client) TrustDir(path string) error {
	resp, err := c.call(rpcRequest{Method: "TrustDir", Resource: path})
	if err != nil {
		return fmt.Errorf("broker: trust dir: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("broker: %s", resp.Error)
	}
	return nil
}

// UntrustDir revokes a directory's trust.
func (c *Client) UntrustDir(path string) error {
	resp, err := c.call(rpcRequest{Method: "UntrustDir", Resource: path})
	if err != nil {
		return fmt.Errorf("broker: untrust dir: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("broker: %s", resp.Error)
	}
	return nil
}

// ListDevDirs returns the trusted developer directories as a JSON array string.
func (c *Client) ListDevDirs() string {
	resp, err := c.call(rpcRequest{Method: "ListDevDirs"})
	if err != nil || resp.Error != "" {
		return "[]"
	}
	if resp.Permissions == "" {
		return "[]"
	}
	return resp.Permissions
}

// RequestDevShell asks the broker (host-side dialog) to open the developer
// environment. Returns true only on explicit user confirmation.
func (c *Client) RequestDevShell() bool {
	resp, err := c.call(rpcRequest{Method: "RequestDevShell"})
	if err != nil {
		return false
	}
	return resp.Trusted
}

// IsAppTrusted checks if an app has blanket permission.
func (c *Client) IsAppTrusted(appExe string) bool {
	resp, err := c.call(rpcRequest{Method: "IsAppTrusted", App: appExe})
	if err != nil {
		return false
	}
	return resp.Trusted
}

// RevokePermission revokes a permanent permission.
func (c *Client) RevokePermission(category, resource string) error {
	resp, err := c.call(rpcRequest{Method: "RevokePermission", Category: category, Resource: resource})
	if err != nil {
		return fmt.Errorf("broker: revoke: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("broker: %s", resp.Error)
	}
	return nil
}

// IsAvailable reports whether the broker control socket accepts connections.
func IsAvailable() bool {
	conn, err := net.DialTimeout("unix", SocketPath(), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
