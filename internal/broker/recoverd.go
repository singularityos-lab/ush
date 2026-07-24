// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// recoverd.go verifies the user's PIN through sinty-recoverd, which owns PIN
// verification, is SO_PEERCRED gated, and rate limits attempts.
//
// The broker makes this call itself instead of trusting a caller's claim that
// the PIN was already checked; only performing the call proves it.
//
// Arming consent is gated on the PIN, not a confirm dialog. A dialog shows a
// human at the console said yes, but on a stolen or seized live session only the
// PIN shows that human is the owner. One action, one prompt.
//
// The PIN is never logged, audited or kept: it is passed to recoverd and dropped.
package broker

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultRecoverdSocket is sinty-recoverd's control socket.
const defaultRecoverdSocket = "/run/sinty-recoverd.sock"

// recoverdTimeout bounds a verification. recoverd is local; a hang must become a
// refusal rather than a stuck desktop.
const recoverdTimeout = 5 * time.Second

// recoverdSocketPath returns the recoverd socket, overridable via
// USH_RECOVERD_SOCK for a test harness, matching USH_BROKER_SOCK.
func recoverdSocketPath() string {
	if p := os.Getenv("USH_RECOVERD_SOCK"); p != "" {
		return p
	}
	return defaultRecoverdSocket
}

// pinWellFormed rejects a PIN the broker must not put on the wire. The recoverd
// protocol is newline delimited, so a PIN containing a newline could close the
// pin field early and append attacker-chosen protocol lines. Refuse it here
// instead of relying on recoverd to survive it.
func pinWellFormed(pin string) bool {
	if pin == "" {
		return false
	}
	return !strings.ContainsAny(pin, "\r\n")
}

// verifyPIN asks recoverd whether pin is the PIN of uid. It returns (true, nil)
// only on an explicit OK. A wrong PIN is (false, nil); anything that prevents an
// answer is an error, and every caller treats both as a refusal.
func verifyPIN(uid int, pin string) (bool, error) {
	conn, err := net.DialTimeout("unix", recoverdSocketPath(), recoverdTimeout)
	if err != nil {
		return false, fmt.Errorf("recoverd unreachable: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(recoverdTimeout)
	_ = conn.SetDeadline(deadline)

	req := "verify\n" + strconv.Itoa(uid) + "\n" + pin + "\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return false, fmt.Errorf("recoverd: write: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("recoverd: no answer: %w", err)
	}
	return strings.TrimSpace(line) == "OK", nil
}
