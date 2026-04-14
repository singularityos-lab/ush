// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"testing"
)

func TestBuildBlockFilter(t *testing.T) {
	blocked := []uint32{101, 321, 308}
	filter := buildBlockFilter(blocked)

	if len(filter) < 5 {
		t.Errorf("filter len = %d, want >= 5 (arch check + syscall checks + default)", len(filter))
	}

	lastInsn := filter[len(filter)-1]
	// Last instruction must be ALLOW (SECCOMP_RET_ALLOW = 0x7FFF0000).
	expectedRet := uint32(0x7FFF0000)
	if lastInsn.K != expectedRet {
		t.Errorf("last insn K = 0x%x, want 0x%x (SECCOMP_RET_ALLOW)", lastInsn.K, expectedRet)
	}
}

func TestBuildNotifyFilter(t *testing.T) {
	notify := []uint32{59, 322}
	block := []uint32{101, 308}

	filter := buildNotifyFilter(notify, block)

	if len(filter) < 8 {
		t.Errorf("filter len = %d, want >= 8", len(filter))
	}

	lastInsn := filter[len(filter)-1]
	expectedRet := uint32(0x7FFF0000)
	if lastInsn.K != expectedRet {
		t.Errorf("last insn K = 0x%x, want 0x%x (SECCOMP_RET_ALLOW)", lastInsn.K, expectedRet)
	}
}

func TestBpfInsn(t *testing.T) {
	stmt := bpfStmt(0x00, 42)
	if stmt.Code != 0x00 || stmt.K != 42 {
		t.Errorf("bpfStmt: got code=%d k=%d, want code=0 k=42", stmt.Code, stmt.K)
	}

	jmp := bpfJump(0x15, 100, 1, 2)
	if jmp.Jt != 1 || jmp.Jf != 2 || jmp.K != 100 {
		t.Errorf("bpfJump: got jt=%d jf=%d k=%d, want jt=1 jf=2 k=100", jmp.Jt, jmp.Jf, jmp.K)
	}
}

func TestSafeDevPath(t *testing.T) {
	tests := []string{
		"/dev/shm",
		"/dev/shm/sem.foo",
		"/dev/fd/1",
		"/dev/pts/0",
		"/dev/stdout",
	}

	for _, path := range tests {
		if !isSafeDevPath(path) {
			t.Errorf("isSafeDevPath(%q) = false, want true", path)
		}
	}
}

func TestUnsafeDevPath(t *testing.T) {
	tests := []string{
		"/dev/kvm",
		"/dev/sda",
		"/dev/input/event0",
		"/dev/shmattack",
	}

	for _, path := range tests {
		if isSafeDevPath(path) {
			t.Errorf("isSafeDevPath(%q) = true, want false", path)
		}
	}
}
