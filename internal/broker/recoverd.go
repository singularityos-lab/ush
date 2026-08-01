// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// The broker validates PIN framing before relaying it to the root recovery
// agent, which performs the authoritative owner check.
package broker

import "strings"

// pinWellFormed rejects control framing before the PIN reaches a privileged
// process. The root agent repeats the same validation before invoking sintykey.
func pinWellFormed(pin string) bool {
	if pin == "" {
		return false
	}
	return !strings.ContainsAny(pin, "\r\n")
}
