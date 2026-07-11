// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package preload provides the C source for the USH LD_PRELOAD shim.
// The C source is compiled at runtime by the guest filesystem setup and
// injected via LD_PRELOAD when running apt/dpkg commands.
package preload

import _ "embed"

// DpkgShimC is the C source for the LD_PRELOAD shim that makes dpkg
// maintainer scripts succeed when they attempt operations that fail inside
// the USH guest namespace:
//   - chown/lchown/fchown/fchownat: unmapped GIDs -> EPERM/EINVAL -> return 0
//   - unlink/unlinkat/rmdir: RO filesystem -> EPERM/EROFS/EACCES -> return 0
//   - symlink: RO filesystem -> EPERM/EROFS/EACCES -> return 0
//   - chmod/fchmod/fchmodat: RO or unmapped -> EPERM/EROFS -> return 0
//   - rename: cross-mount or RO -> EPERM/EROFS/EXDEV -> return 0
//   - link/linkat: RO filesystem -> EPERM/EROFS -> return 0
//   - mkdir/mkdirat/creat: RO filesystem -> EPERM/EROFS/EACCES -> return 0
//
//go:embed csrc/ush-chown-shim.c
var DpkgShimC string
