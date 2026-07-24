// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// origin.go attributes a permission request to where it came from. Every request
// used to reach the broker over the private control socket from the local
// sandbox, so a user answering a dialog knew the action started on this machine.
// The debug bridge (sdb) breaks that: a paired development host can drive the
// same client API from another machine. Such a connection does NOT grant root;
// it stays an ordinary broker client with the same per-action approval.
//
// The origin is carried as one extra field on the request, used for two things:
//
//   - the dialog says the action was requested REMOTELY, and by which paired
//     host label
//   - a remote request can only be narrowed: it does not read the policy cache,
//     join a local in-flight prompt, or persist a rule, so a past local "always
//     allow" cannot answer for it
//
// Origin can only make a request stricter, so a client lying about it (a local
// guest claiming remote) gains nothing. Parsing is fail-closed: any unrecognised
// value is treated as remote, never local.
package broker

import "strings"

// OriginKindSDB marks a request relayed by the debug bridge daemon on behalf of
// a paired development host.
const OriginKindSDB = "sdb"

// Origin describes where a permission request was started.
type Origin struct {
	// Remote is true when the request did not start on this machine.
	Remote bool
	// Kind is the transport that carried it, empty for local.
	Kind string
	// Label is the human-readable name of the remote peer (the paired host
	// label), empty when it is not known.
	Label string
}

// SDBOrigin builds the origin string the debug bridge daemon puts on a request
// it relays for the paired host named hostLabel.
func SDBOrigin(hostLabel string) string {
	return OriginKindSDB + ":" + hostLabel
}

// parseOrigin turns the wire value into an Origin. An empty value is the local
// control socket (every pre-existing client sends nothing and keeps behaving
// exactly as before). Anything that is not a recognised form is remote with an
// unknown peer: an unparseable origin must never be promoted to local.
func parseOrigin(raw string) Origin {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "" || raw == "local":
		return Origin{}
	case strings.HasPrefix(raw, OriginKindSDB+":"):
		return Origin{
			Remote: true,
			Kind:   OriginKindSDB,
			Label:  strings.TrimSpace(strings.TrimPrefix(raw, OriginKindSDB+":")),
		}
	default:
		return Origin{Remote: true, Kind: "unknown"}
	}
}

// banner is the line prepended to the dialog reason for a remote request. It is
// the only thing that tells the user the action was not started here, so it goes
// first and it names the peer when one is known.
func (o Origin) banner() string {
	if !o.Remote {
		return ""
	}
	who := o.Label
	if o.Kind != OriginKindSDB || who == "" {
		return "REQUESTED REMOTELY over the debug bridge by an UNIDENTIFIED host."
	}
	return "REQUESTED REMOTELY over the debug bridge by paired host: " + dialogSafe(who) + "."
}

// auditValue is the origin as recorded in the audit log.
func (o Origin) auditValue() string {
	if !o.Remote {
		return ""
	}
	if o.Label == "" {
		return o.Kind
	}
	return o.Kind + ":" + o.Label
}
