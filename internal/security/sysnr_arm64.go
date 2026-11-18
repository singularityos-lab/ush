// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package security

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_AARCH64
	rejectX32 = false
)

var legacyCalls = map[uint32]callKind{}
