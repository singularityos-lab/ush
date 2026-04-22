// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package guardsink forwards ush supervisor telemetry to the Singularity Guard
// daemon (singd) over a Unix socket, as JSON lines.
//
// Design constraints:
//   - It must NEVER block the seccomp-notify supervisor: a slow or absent singd
//     cannot be allowed to stall a guest syscall. Emit() is a non-blocking send
//     onto a bounded channel; if the channel is full the event is dropped.
//   - It must NEVER crash ush: connection errors are swallowed and retried
//     lazily. If singd is not running, events are simply discarded.
package guardsink

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/singularityos-lab/ush/internal/guardproto"
	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// Client is an asynchronous, best-effort telemetry forwarder.
type Client struct {
	ch      chan guardproto.Event
	socket  string
	session string

	mu   sync.Mutex
	conn net.Conn
}

// New creates a Client and starts its background sender. It always returns a
// usable Client: if singd is not reachable the events are dropped silently.
func New(sessionID string) *Client {
	c := &Client{
		ch:      make(chan guardproto.Event, 1024),
		socket:  guardproto.EventsSocket(),
		session: sessionID,
	}
	go c.run()
	return c
}

// EmitGuardEvent implements the security.EventSink interface. Non-blocking:
// drops the event if the buffer is full rather than stalling the caller.
func (c *Client) EmitGuardEvent(e guardproto.Event) {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if e.Session == "" {
		e.Session = c.session
	}
	select {
	case c.ch <- e:
	default:
		// Buffer full: drop. Detection tolerates gaps by design.
	}
}

func (c *Client) run() {
	for e := range c.ch {
		c.send(e)
	}
}

func (c *Client) send(e guardproto.Event) {
	conn := c.dial()
	if conn == nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(data); err != nil {
		c.drop()
	}
}

// dial returns a live connection, reconnecting lazily. Returns nil if singd is
// unreachable (the common case when the guard daemon is not installed).
func (c *Client) dial() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn
	}
	conn, err := net.DialTimeout("unix", c.socket, 500*time.Millisecond)
	if err != nil {
		return nil
	}
	ushlog.Debug("guardsink: connected to singd", "socket", c.socket)
	c.conn = conn
	return c.conn
}

func (c *Client) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
