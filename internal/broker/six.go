// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"fmt"
	"os"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// sixStatus reports whether the init offers the experimental kernel switch
// and its state: "off", "on" (opted in, not yet staged) or "ready" (the next
// boot tries the new kernel and falls back on its own if it does not start).
func (s *Server) sixStatus() (available bool, state string) {
	rep, err := atomSDBControlCall(atomRequest{Cmd: "six-status"})
	if err != nil || !rep.OK {
		return false, "off"
	}
	return true, rep.State
}

// setSixEnabled flips the opt-in through the init's fixed command. Like the
// debug bridge switch it is refused for remote origins and unverified peers.
func (s *Server) setSixEnabled(enabled bool, origin Origin, peer peerIdentity) (ok bool, state string, message string) {
	_, current := s.sixStatus()
	if origin.Remote {
		ushlog.Warn("broker: kernel switch refused, request is not local", "origin", origin.auditValue())
		return false, current, msgSdbRemoteRefused
	}
	if !peer.isOwner(uint32(os.Getuid())) {
		ushlog.Warn("broker: kernel switch from unverified peer", "peer_known", peer.known)
		return false, current, msgPeerUnverified
	}
	cmd := "six-disable"
	if enabled {
		cmd = "six-enable"
	}
	rep, err := atomSDBControlCall(atomRequest{Cmd: cmd})
	if err != nil {
		return false, current, err.Error()
	}
	if !rep.OK {
		return false, current, fmt.Sprintf("init control: %s: %s", cmd, atomError(rep))
	}
	ushlog.Info("broker: kernel switch", "enable", enabled, "state", rep.State)
	return (rep.State != "off") == enabled, rep.State, ""
}
