// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// atomctl.go drives the init's control socket, which starts and stops services
// on this target. PID 1 listens on /run/atom/control.sock and speaks
// length-prefixed JSON frames: a 4-byte big-endian length followed by the body.
//
// Only start/stop are available, not enable/disable: under this init enablement
// is the set of <target>.wants symlinks baked into the erofs+dm-verity image,
// mounted read-only, so there is no live enable to call.
//
// The protocol is reimplemented rather than imported: it is one request and one
// reply, and depending on the init module would couple the broker's build to
// PID 1's.
package broker

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const defaultAtomControlSocket = "/run/atom/control.sock"
const defaultAtomSDBControlSocket = "/run/atom/sdb-control.sock"

const (
	atomDialTimeout = 3 * time.Second
	atomCallTimeout = 70 * time.Second // the init bounds a mutation at 60s
	atomMaxFrame    = 8 << 20
)

func atomControlSocketPath() string {
	if p := os.Getenv("USH_ATOM_CONTROL_SOCK"); p != "" {
		return p
	}
	return defaultAtomControlSocket
}

func atomSDBControlSocketPath() string {
	if p := os.Getenv("USH_ATOM_SDB_CONTROL_SOCK"); p != "" {
		return p
	}
	if p := os.Getenv("USH_ATOM_CONTROL_SOCK"); p != "" {
		return p
	}
	return defaultAtomSDBControlSocket
}

type atomRequest struct {
	Cmd  string `json:"cmd"`
	Unit string `json:"unit,omitempty"`
}

type atomUnitStatus struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	State string `json:"state"`
}

type atomReply struct {
	OK    bool             `json:"ok"`
	Error string           `json:"error,omitempty"`
	State string           `json:"state,omitempty"`
	Units []atomUnitStatus `json:"units,omitempty"`
}

func atomWriteFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > atomMaxFrame {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func atomReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > atomMaxFrame {
		return fmt.Errorf("frame too large: %d bytes", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// atomControlCall sends one request to PID 1 and returns the reply. Every
// failure is an error; a reply that merely arrived is not a success.
func atomControlCallAt(path string, req atomRequest) (atomReply, error) {
	conn, err := net.DialTimeout("unix", path, atomDialTimeout)
	if err != nil {
		return atomReply{}, fmt.Errorf("init control unreachable at %s: %w", path, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(atomCallTimeout))
	if err := atomWriteFrame(conn, req); err != nil {
		return atomReply{}, fmt.Errorf("init control: write: %w", err)
	}
	var rep atomReply
	if err := atomReadFrame(conn, &rep); err != nil {
		return atomReply{}, fmt.Errorf("init control: read: %w", err)
	}
	return rep, nil
}

func atomControlCall(req atomRequest) (atomReply, error) {
	return atomControlCallAt(atomControlSocketPath(), req)
}

func atomSDBControlCall(req atomRequest) (atomReply, error) {
	return atomControlCallAt(atomSDBControlSocketPath(), req)
}

func atomSessionPower(cmd string) error {
	if cmd != "session-reboot" && cmd != "session-poweroff" {
		return fmt.Errorf("unsupported session power action: %s", cmd)
	}
	rep, err := atomSDBControlCall(atomRequest{Cmd: cmd})
	if err != nil {
		return err
	}
	if !rep.OK {
		return fmt.Errorf("init control: %s: %s", cmd, atomError(rep))
	}
	return nil
}

// atomSdbService controls the debug bridge unit through the init.
type atomSdbService struct{}

// Present reports whether the unit file is known to the init. status also sees
// units outside the boot graph without starting them.
func (atomSdbService) Present() (bool, error) {
	rep, err := atomSDBControlCall(atomRequest{Cmd: "sdb-status"})
	if err != nil {
		return false, err
	}
	if !rep.OK {
		return false, fmt.Errorf("init control: status: %s", atomError(rep))
	}
	return rep.State != "unknown" && rep.State != "not-found", nil
}

// SetEnabled asks PID 1 to update both the persistent gate and live state. The
// dedicated socket accepts no arbitrary unit name or general init operation.
func (atomSdbService) SetEnabled(on bool) error {
	cmd := "sdb-disable"
	if on {
		cmd = "sdb-enable"
	}
	rep, err := atomSDBControlCall(atomRequest{Cmd: cmd})
	if err != nil {
		return err
	}
	if !rep.OK {
		return fmt.Errorf("init control: %s: %s", cmd, atomError(rep))
	}
	return nil
}

func atomError(rep atomReply) string {
	if rep.Error == "" {
		return "no reason given"
	}
	return rep.Error
}
