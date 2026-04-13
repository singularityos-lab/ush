// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"testing"
)

func TestAbiHandledFS(t *testing.T) {
	tests := []struct {
		abi  int
		want uint64
	}{
		{1, landlockAccessFSV1},
		{2, landlockAccessFSV2},
		{3, landlockAccessFSV3},
		{4, landlockAccessFSV4},
		{5, landlockAccessFSV4},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := abiHandledFS(tt.abi)
			if got != tt.want {
				t.Errorf("abiHandledFS(%d) = 0x%x, want 0x%x", tt.abi, got, tt.want)
			}
		})
	}
}

func TestGuestLandlockConfig(t *testing.T) {
	cfg := GuestLandlockConfig("/home/user", "/run/user/1000", "/home/user/.local/share/ush")

	if len(cfg.ROPaths) != 1 || cfg.ROPaths[0] != "/" {
		t.Errorf("ROPaths = %v, want [/]", cfg.ROPaths)
	}

	rwSet := make(map[string]bool)
	for _, p := range cfg.RWPaths {
		rwSet[p] = true
	}

	for _, expected := range []string{"/tmp", "/run", "/var", "/etc", "/dev", "/home/user", "/run/user/1000"} {
		if !rwSet[expected] {
			t.Errorf("RWPaths missing %q", expected)
		}
	}
}

func TestGuestLandlockConfigMinimal(t *testing.T) {
	cfg := GuestLandlockConfig("", "", "")

	if len(cfg.RWPaths) != 5 {
		t.Errorf("len(RWPaths) = %d, want 5 (no home/xdg when empty)", len(cfg.RWPaths))
	}
}

func TestReadOnlyAccess(t *testing.T) {
	// EXECUTE=0x1 | READ_FILE=0x4 | READ_DIR=0x8 = 0xd
	expected := uint64(0xd)
	if readOnlyAccess != expected {
		t.Errorf("readOnlyAccess = 0x%x, want 0x%x", readOnlyAccess, expected)
	}
}
