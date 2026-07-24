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
	"path/filepath"
	"time"
)

const defaultAtomControlSocket = "/run/atom/control.sock"

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

// defaultSdbOptIn is the per-bridge marker sdbd and its unit both require. It is
// deliberately NOT the development marker: that one governs the whole image and
// lives on the read-only verity tree, while this one governs the bridge alone
// and lives on writable storage. Absent means off, so a fresh image carries no
// listener until the owner asks for one.
const defaultSdbOptIn = "/var/lib/sinty-sdb/enabled"

func sdbOptInPath() string {
	if p := os.Getenv("USH_SDB_OPT_IN"); p != "" {
		return p
	}
	return defaultSdbOptIn
}

// setSdbOptIn creates or removes the marker. Removal treats an already-absent
// marker as done, so turning off a bridge that is already off is not an error.
func setSdbOptIn(on bool) error {
	path := sdbOptInPath()
	if !on {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("sdb opt-in: remove %s: %w", path, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("sdb opt-in: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("sdb opt-in: create %s: %w", path, err)
	}
	return f.Close()
}

// sdbUnitName is the unit the debug bridge runs as. It is overridable because
// the unit is shipped by the image rather than by this repository; if the name
// is wrong, Present reports false and the desktop greys the control out, which
// is the safe direction.
func sdbUnitName() string {
	if n := os.Getenv("USH_SDB_UNIT"); n != "" {
		return n
	}
	// The image ships the bridge as sdbd.service (package sinty-sdb installs
	// dist/sdbd.service). sinit reports and keys units by their full file name,
	// so the broker must match that exactly, including the .service suffix.
	return "sdbd.service"
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
func atomControlCall(req atomRequest) (atomReply, error) {
	conn, err := net.DialTimeout("unix", atomControlSocketPath(), atomDialTimeout)
	if err != nil {
		return atomReply{}, fmt.Errorf("init control unreachable: %w", err)
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

// atomSdbService controls the debug bridge unit through the init.
type atomSdbService struct{}

// Present reports whether the unit is known to the init. list-units needs no
// privilege, so this answers even where a mutation would be refused.
func (atomSdbService) Present() (bool, error) {
	rep, err := atomControlCall(atomRequest{Cmd: "list-units"})
	if err != nil {
		return false, err
	}
	if !rep.OK {
		return false, fmt.Errorf("init control: list-units: %s", atomError(rep))
	}
	want := sdbUnitName()
	for _, u := range rep.Units {
		if u.Name == want {
			return true, nil
		}
	}
	return false, nil
}

// SetEnabled switches the bridge in both halves: the persistent marker, then the
// live state. It deliberately does not attempt to change unit enablement, which
// does not exist as a live operation here (see the file comment).
//
// The marker always moves FIRST, in both directions, and the init command is
// issued only if that succeeded. The ordering is the safety property: a crash
// between the two steps must leave the closed state, never the open one.
//
//   - disabling removes the marker before the stop, so an interrupted disable
//     leaves a bridge that is not allowed to come back at next boot
//   - enabling creates it before the start, so an interrupted enable leaves a
//     bridge that is allowed but not running, which the next status read reports
//     honestly as inactive
//
// A marker that cannot be written is a hard failure and no init command is sent:
// changing the live state while the persistent state stayed behind is exactly
// the disagreement this ordering exists to prevent.
func (atomSdbService) SetEnabled(on bool) error {
	if err := setSdbOptIn(on); err != nil {
		return err
	}

	cmd := "stop"
	if on {
		cmd = "start"
	}
	rep, err := atomControlCall(atomRequest{Cmd: cmd, Unit: sdbUnitName()})
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
