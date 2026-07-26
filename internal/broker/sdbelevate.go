// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// sdbelevate.go mediates the privileged actions of SDB phase 2. The debug bridge
// daemon (sdbd) has no privileges of its own: when a paired host asks for a root
// shell, a write outside the transfer root, or a privileged port, sdbd does
// NOT act on it directly. It relays the request here, as an ordinary broker
// client, and the broker asks the person at the device for a per-action
// approval, exactly as it does for any other remote request.
//
// Two properties make this safe:
//
//   - It is always the REMOTE path. An elevation started by the bridge is never
//     local, so the request is forced remote here even if the caller omitted the
//     origin: the dialog always shows the remote banner, the request never reads
//     a local "always allow" rule, and it is never remembered.
//   - It is fail-closed. An unknown action, a missing required argument, or the
//     absence of a user to approve (headless / scripted mode) all deny WITHOUT
//     acting. sdbd, on a denial, keeps the action unprivileged; it never fails
//     silent into a privileged state.
//
// Path confinement for write-system is sdbd's job and happens BEFORE this call:
// a path that escapes the bridge root is an attack and is rejected there. What
// reaches the broker is a privilege question on an already-confined path, and
// the broker mediates only that.
package broker

import "strings"

// The privilege kinds a bridge peer may ask for. Anything else is refused.
const (
	sdbElevateShellRoot          = "shell-root"
	sdbElevateWriteSystem        = "write-system"
	sdbElevateBindPrivilegedPort = "bind-privileged-port"
	// sdbElevateAssist is tier 3: a bounded, read-only assistance session. It is
	// NOT a privilege escalation to root; it is mediated so the person at the
	// device sees, and consents to, a remote host starting an assistance probe.
	sdbElevateAssist = "assist"
)

// sdbElevateCategory is the audit/dialog category for every elevation request.
const sdbElevateCategory = "sdb-elevate"

// sdbElevate answers one privileged-action request relayed by sdbd. It returns
// whether the action is granted and a short reason suitable for the bridge to
// surface. It never acts on anything itself; granting only means the caller (sdbd)
// may now perform the action it described.
func (s *Server) sdbElevate(action, detail, sessionID string, origin Origin) (granted bool, reason string) {
	// An elevation is always a bridge action. Force the remote path so a caller
	// that sent no origin (or a local one) still gets the remote banner and the
	// narrowed, never-remembered handling.
	if !origin.Remote {
		origin = Origin{Remote: true, Kind: "unknown"}
	}

	resource, prompt, denyReason, ok := sdbElevateDescribe(action, detail)
	if !ok {
		// Malformed request: refuse without ever prompting the user.
		return false, denyReason
	}

	// Tier 2 gate: a ROOT shell is only ever offered on a rooted device, i.e. one
	// whose bootloader is unlocked. Check that BEFORE prompting, and fail closed:
	// a locked device, or a lock state we cannot read, refuses without a dialog.
	// A user cannot approve their way to root on a locked device.
	if action == sdbElevateShellRoot {
		st, err := s.bootloaderLockState()
		if err != nil {
			return false, "device root state unavailable: root shell refused"
		}
		if st.Locked {
			return false, "device is locked (not rooted): root shell refused"
		}
	}

	decision := s.requestRemotePermission(sdbElevateCategory, resource, prompt, sessionID, origin)
	if decision == "allow" {
		return true, "granted"
	}
	return false, "denied"
}

// sdbElevateDescribe validates one request and renders the dialog resource and
// prompt for it. ok is false for an unknown action or a missing required
// argument, with denyReason carrying the machine-readable cause.
func sdbElevateDescribe(action, detail string) (resource, prompt, denyReason string, ok bool) {
	detail = strings.TrimSpace(detail)
	switch action {
	case sdbElevateShellRoot:
		return sdbElevateShellRoot,
			"Open a ROOT shell on this device over the debug bridge.",
			"", true
	case sdbElevateWriteSystem:
		if detail == "" {
			return "", "", "write-system requires a target path", false
		}
		return sdbElevateWriteSystem + ":" + detail,
			"Write to the system path " + detail + " over the debug bridge.",
			"", true
	case sdbElevateBindPrivilegedPort:
		if detail == "" {
			return "", "", "bind-privileged-port requires a port", false
		}
		return sdbElevateBindPrivilegedPort + ":" + detail,
			"Bind privileged port " + detail + " over the debug bridge.",
			"", true
	case sdbElevateAssist:
		return sdbElevateAssist,
			"Start a bounded, read-only assistance session over the debug bridge.",
			"", true
	default:
		return "", "", "unknown elevation action", false
	}
}
