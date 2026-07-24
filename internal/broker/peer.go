// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// peer.go reads the kernel-attested credentials (SO_PEERCRED) of whoever is on
// the other end of the control socket. The socket is already owner-only (0600),
// but that mode can be changed by whoever owns the path, while SO_PEERCRED is
// filled in by the kernel at connect time and cannot be forged; so this is a
// second, independent check.
//
// It gates the operations that reach a privileged agent on the caller's behalf,
// where the broker being privileged is only safe if it knows who the caller is.
package broker

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerIdentity is the kernel-reported identity of the control socket peer.
// A zero value means the credentials could not be read, which every caller
// treats as untrusted.
type peerIdentity struct {
	known bool
	uid   uint32
	gid   uint32
	pid   int32
}

// peerFromConn reads SO_PEERCRED from a unix connection. Any failure returns the
// zero peerIdentity (known == false) rather than an error, because there is no
// recovery: the caller refuses either way.
func peerFromConn(conn net.Conn) peerIdentity {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peerIdentity{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerIdentity{}
	}

	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peerIdentity{}
	}
	if credErr != nil || cred == nil {
		return peerIdentity{}
	}

	return peerIdentity{
		known: true,
		uid:   cred.Uid,
		gid:   cred.Gid,
		pid:   cred.Pid,
	}
}

// isOwner reports whether the peer is the user the broker runs as. The broker
// acts on the desktop user's behalf, so a connection from any other uid is not
// something it should be relaying to a privileged agent.
func (p peerIdentity) isOwner(brokerUID uint32) bool {
	return p.known && p.uid == brokerUID
}
