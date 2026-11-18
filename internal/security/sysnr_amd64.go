// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package security

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	rejectX32 = true
)

var legacyCalls = map[uint32]callKind{
	unix.SYS_OPEN:   callOpen,
	unix.SYS_CREAT:  callCreat,
	unix.SYS_CHMOD:  callChmod,
	unix.SYS_UNLINK: callUnlink,
	unix.SYS_RMDIR:  callUnlink,
	unix.SYS_RENAME: callRename,
}
