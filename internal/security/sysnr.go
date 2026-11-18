// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package security

import (
	"sort"

	"golang.org/x/sys/unix"
)

type callKind uint8

const (
	callOther callKind = iota
	callExec
	callSocket
	callConnect
	callOpen
	callOpenat
	callOpenat2
	callCreat
	callMount
	callChmod
	callFchmod
	callFchmodat
	callUnlink
	callUnlinkat
	callRename
	callRenameat
)

var genericCalls = map[uint32]callKind{
	unix.SYS_EXECVE:    callExec,
	unix.SYS_EXECVEAT:  callExec,
	unix.SYS_SOCKET:    callSocket,
	unix.SYS_CONNECT:   callConnect,
	unix.SYS_OPENAT:    callOpenat,
	unix.SYS_OPENAT2:   callOpenat2,
	unix.SYS_MOUNT:     callMount,
	unix.SYS_FCHMOD:    callFchmod,
	unix.SYS_FCHMODAT:  callFchmodat,
	unix.SYS_FCHMODAT2: callFchmodat,
	unix.SYS_UNLINKAT:  callUnlinkat,
	unix.SYS_RENAMEAT:  callRenameat,
	unix.SYS_RENAMEAT2: callRenameat,
}

func kindOf(nr int32) callKind {
	if k, ok := genericCalls[uint32(nr)]; ok {
		return k
	}
	return legacyCalls[uint32(nr)]
}

func callsOf(kinds ...callKind) []uint32 {
	want := make(map[callKind]bool, len(kinds))
	for _, k := range kinds {
		want[k] = true
	}
	var nrs []uint32
	for _, table := range []map[uint32]callKind{genericCalls, legacyCalls} {
		for nr, k := range table {
			if want[k] {
				nrs = append(nrs, nr)
			}
		}
	}
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })
	return nrs
}

func archCheck(onX32 unix.SockFilter) []unix.SockFilter {
	insns := []unix.SockFilter{
		bpfStmt(bpfLD|bpfW|bpfABS, archOffset),
		bpfJump(bpfJMP|bpfJEQ|bpfK, auditArch, 1, 0),
		bpfStmt(bpfRET|bpfK, unix.SECCOMP_RET_KILL),
		bpfStmt(bpfLD|bpfW|bpfABS, syscallNROffset),
	}
	if rejectX32 {
		insns = append(insns,
			bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
			onX32,
		)
	}
	return insns
}
