// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package arch maps Go architectures to the names Debian uses for them.
package arch

import (
	"fmt"
	"runtime"
)

type names struct {
	debian  string
	triplet string
}

var known = map[string]names{
	"amd64": {debian: "amd64", triplet: "x86_64-linux-gnu"},
	"arm64": {debian: "arm64", triplet: "aarch64-linux-gnu"},
}

// Debian returns the Debian architecture of the running binary.
func Debian() string { return known[runtime.GOARCH].debian }

// Triplet returns the Debian multiarch triplet of the running binary.
func Triplet() string { return known[runtime.GOARCH].triplet }

// DebianFor returns the Debian architecture for a Go architecture name.
func DebianFor(goarch string) (string, error) {
	n, ok := known[goarch]
	if !ok {
		return "", fmt.Errorf("arch: unsupported architecture %q", goarch)
	}
	return n.debian, nil
}
