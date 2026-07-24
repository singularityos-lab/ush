// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// bootloader.go relays bootloader-unlock consent to the privileged recovery
// agent on /run/atom-recovery.sock (root:root, 0660). The desktop user cannot
// open that socket; the broker, already privileged, makes the call on its behalf
// so the agent keeps a single caller.
//
// Arming is gated three ways before the agent is contacted:
//
//   - origin must be local; a request from the debug bridge is refused, so a
//     paired remote host cannot arm unlock even with a human at the local screen
//   - peer credentials (SO_PEERCRED) must be the broker's own user
//   - the PIN must verify against sinty-recoverd (see recoverd.go): any local
//     process, including the sandboxed guest, can reach the control surface, so
//     only the PIN proves the caller is the owner
//
// Disarming removes consent, so it is fail-safe: no PIN, remote callers allowed,
// never blocked. A failed disarm is still reported as failed.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// defaultAtomRecoverySocket is where the privileged recovery agent listens.
const defaultAtomRecoverySocket = "/run/atom-recovery.sock"

// atomRecoveryTimeout bounds every call to the agent. The agent is local and
// answers immediately; a hang must surface as a refusal, not as a stuck dialog.
const atomRecoveryTimeout = 5 * time.Second

// atomRecoverySocketPath returns the agent socket, overridable via
// USH_ATOM_RECOVERY_SOCK so a test harness can point the broker at a mock (the
// same affordance USH_BROKER_SOCK provides for the control socket).
func atomRecoverySocketPath() string {
	if p := os.Getenv("USH_ATOM_RECOVERY_SOCK"); p != "" {
		return p
	}
	return defaultAtomRecoverySocket
}

// User-facing refusal messages. The desktop displays these verbatim, so they say
// what happened and what to do, and they never leak internals.
const (
	msgRemoteRefused  = "Bootloader unlock cannot be armed over the debug bridge. Do it on the device itself."
	msgPeerUnverified = "The request could not be attributed to your account and was refused."
	msgPINRequired    = "Enter your PIN to allow bootloader unlock."
	msgPINWrong       = "Incorrect PIN. Bootloader unlock was not allowed."
	msgPINUnavailable = "Your PIN could not be checked right now. Nothing was changed."
)

// LockState is the bootloader lock state as reported by the recovery agent.
type LockState struct {
	Locked      bool `json:"locked"`
	UnlockArmed bool `json:"unlock_armed"`
	UnlockCount int  `json:"unlock_count"`
}

// armReply is the recovery agent's answer to POST /arm-unlock.
type armReply struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// atomRecoveryClient speaks HTTP/1.1 to the agent over its unix socket. Keep
// alives are disabled so each call is a self-contained connection that the agent
// closes when it is done.
func atomRecoveryClient() *http.Client {
	return &http.Client{
		Timeout: atomRecoveryTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", atomRecoverySocketPath())
			},
		},
	}
}

// atomRecoveryCall performs one request against the agent and decodes the JSON
// body into out. Every unexpected condition is an error: an unreachable socket,
// a non-200 status, a body that is not the JSON we expect. None of them may be
// reported to the caller as success.
func atomRecoveryCall(method, path string, body []byte, out interface{}) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://atom-recovery"+path, reader)
	if err != nil {
		return fmt.Errorf("recovery agent: build request: %w", err)
	}
	req.Close = true
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := atomRecoveryClient().Do(req)
	if err != nil {
		return fmt.Errorf("recovery agent unreachable: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("recovery agent: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("recovery agent: status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("recovery agent: unparsable response")
	}
	return nil
}

// bootloaderLockState reads the current lock state. Reading is harmless, so it
// takes no dialog and no origin restriction, but it still fails closed: a caller
// that cannot be told the truth is told nothing.
func (s *Server) bootloaderLockState() (LockState, error) {
	var st LockState
	if err := atomRecoveryCall(http.MethodGet, "/lock-state", nil, &st); err != nil {
		ushlog.Warn("broker: bootloader lock state unavailable", "err", err)
		return LockState{}, err
	}
	return st, nil
}

// setBootloaderUnlockArmed arms or disarms bootloader-unlock consent. See the
// file comment for the gates; the order matters, because a refusal that happens
// before the dialog is a refusal the user is never asked to override.
// The pin is required only for arming and is never logged or audited.
func (s *Server) setBootloaderUnlockArmed(
	armed bool, pin string, origin Origin, peer peerIdentity,
) (armReply, error) {
	action := "disarm"
	if armed {
		action = "arm"
	}

	// A remote request to ARM is refused outright, without a dialog. Prompting
	// would be worse than useless: it would put a yes/no in front of a local user
	// for a decision that a remote host asked for, which is exactly the confusion
	// the origin attribution exists to prevent.
	if armed && origin.Remote {
		ushlog.Warn("broker: bootloader unlock arm refused, request is not local",
			"origin", origin.auditValue())
		s.auditBootloader(action, "deny", "remote_origin_refused", origin)
		return armReply{OK: false, Message: msgRemoteRefused}, fmt.Errorf(
			"arming bootloader unlock is not permitted over the debug bridge")
	}

	if !peer.isOwner(uint32(os.Getuid())) {
		ushlog.Warn("broker: bootloader unlock request from unverified peer",
			"action", action, "peer_known", peer.known)
		s.auditBootloader(action, "deny", "peer_unverified", origin)
		return armReply{OK: false, Message: msgPeerUnverified},
			fmt.Errorf("caller identity could not be verified")
	}

	// Arming requires proof of ownership. Disarming deliberately does not: a user
	// who cannot produce a PIN must still be able to take consent away.
	if armed {
		if !pinWellFormed(pin) {
			ushlog.Warn("broker: bootloader unlock arm rejected, PIN missing or malformed")
			s.auditBootloader(action, "deny", "pin_missing", origin)
			return armReply{OK: false, Message: msgPINRequired},
				fmt.Errorf("a PIN is required to arm bootloader unlock")
		}
		ok, err := verifyPIN(os.Getuid(), pin)
		if err != nil {
			ushlog.Warn("broker: PIN verification unavailable", "err", err)
			s.auditBootloader(action, "error", "pin_verify_failed", origin)
			return armReply{OK: false, Message: msgPINUnavailable}, err
		}
		if !ok {
			ushlog.Warn("broker: bootloader unlock arm refused, PIN did not verify")
			s.auditBootloader(action, "deny", "pin_wrong", origin)
			return armReply{OK: false, Message: msgPINWrong},
				fmt.Errorf("PIN verification failed")
		}
	}

	body, err := json.Marshal(map[string]bool{"armed": armed})
	if err != nil {
		return armReply{}, fmt.Errorf("recovery agent: build body: %w", err)
	}

	var reply armReply
	if err := atomRecoveryCall(http.MethodPost, "/arm-unlock", body, &reply); err != nil {
		ushlog.Warn("broker: bootloader unlock call failed", "action", action, "err", err)
		s.auditBootloader(action, "error", "agent_call_failed", origin)
		return armReply{}, err
	}
	if !reply.OK {
		// The agent refused. Surface its message; never round a refusal up to done.
		ushlog.Warn("broker: recovery agent refused bootloader unlock change",
			"action", action)
		s.auditBootloader(action, "deny", "agent_refused", origin)
		return reply, fmt.Errorf("recovery agent refused: %s", agentMessage(reply.Message))
	}

	ushlog.Info("broker: bootloader unlock consent changed", "action", action)
	s.auditBootloader(action, "allow", "agent_ok", origin)
	return reply, nil
}

// agentMessage keeps the agent's explanation usable when it sends none.
func agentMessage(msg string) string {
	if msg == "" {
		return "no reason given"
	}
	return msg
}

func (s *Server) auditBootloader(action, decision, source string, origin Origin) {
	s.auditLog.Write(AuditEntry{
		Timestamp: time.Now(),
		Category:  "bootloader",
		Resource:  "unlock-consent:" + action,
		Decision:  decision,
		Source:    source,
		Origin:    origin.auditValue(),
	})
}
