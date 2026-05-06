// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package devpolicy decides whether the developer shell (dsh) may run. dsh trades
// app isolation for power, so it must never be on by default and a managed image
// must be able to forbid it outright.
//
// Three layers, highest wins:
//
//  1. Image policy, in the immutable (signed) rootfs at /usr/lib/ush/dsh-policy.
//     On an atomic OS this file is part of the dm-verity-protected tree, so an
//     appliance/enterprise image that ships "forbidden" cannot be overridden on
//     the device.
//  2. Managed override, at /etc/ush/dsh-policy, for fleets that ship "optin" but
//     want central control. Its integrity is the OS's responsibility.
//  3. User opt-in, a marker under the writable ush storage dir, only consulted
//     when the layers above leave the choice to the user.
//
// When no policy file exists (a plain developer box, not an atomic image), the
// default is "optin": dsh is available but stays off until the user enables it.
package devpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Policy is the image-declared stance on dsh.
type Policy string

const (
	Forbidden Policy = "forbidden" // dsh may never run; the user cannot override
	OptIn     Policy = "optin"     // available, off until the user enables it
	Enabled   Policy = "enabled"   // on without a user opt-in
)

// Decision is the resolved verdict for launching dsh right now.
type Decision int

const (
	Allow Decision = iota
	DenyForbidden
	DenyNotEnabled
)

// Paths are vars (not consts) only so tests can redirect them; in production they
// are the fixed locations below.
var (
	imagePolicyPath   = "/usr/lib/ush/dsh-policy" // signed, read-only rootfs
	managedPolicyPath = "/etc/ush/dsh-policy"     // optional managed override
)

const optInFile = "dsh-opt-in" // under the writable storage dir

func readPolicy(path string) (Policy, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	switch p := Policy(strings.TrimSpace(string(b))); p {
	case Forbidden, OptIn, Enabled:
		return p, true
	}
	return "", false
}

// effectivePolicy is the image policy, overridden by a managed policy if present,
// defaulting to OptIn when neither is declared.
func effectivePolicy() Policy {
	p := OptIn
	if ip, ok := readPolicy(imagePolicyPath); ok {
		p = ip
	}
	if mp, ok := readPolicy(managedPolicyPath); ok {
		p = mp
	}
	return p
}

func userOptedIn(storageDir string) bool {
	_, err := os.Stat(filepath.Join(storageDir, optInFile))
	return err == nil
}

// Evaluate resolves whether dsh may launch now.
func Evaluate(storageDir string) Decision {
	switch effectivePolicy() {
	case Forbidden:
		return DenyForbidden
	case Enabled:
		return Allow
	default: // OptIn
		if userOptedIn(storageDir) {
			return Allow
		}
		return DenyNotEnabled
	}
}

// Permitted reports whether the user is allowed to enable dsh at all (the image
// policy is not "forbidden"). The desktop hides the toggle when this is false.
func Permitted() bool { return effectivePolicy() != Forbidden }

// SetUserEnabled writes or clears the user opt-in. It refuses when the image
// policy forbids dsh, so neither the CLI nor the desktop can bypass the image.
func SetUserEnabled(storageDir string, on bool) error {
	if effectivePolicy() == Forbidden {
		return fmt.Errorf("developer shell is disabled by device policy")
	}
	marker := filepath.Join(storageDir, optInFile)
	if !on {
		_ = os.Remove(marker)
		return nil
	}
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return err
	}
	return os.WriteFile(marker, []byte("1\n"), 0600)
}

// Status returns the effective policy string and whether dsh is enabled now.
func Status(storageDir string) (policy string, enabled bool) {
	return string(effectivePolicy()), Evaluate(storageDir) == Allow
}
