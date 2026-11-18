// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"os"
	"os/exec"
	"testing"
)

func TestLandlockProcWriteDenied(t *testing.T) {
	if os.Getenv("USH_TEST_LANDLOCK_PROC") == "1" {
		if err := ApplyLandlock(LandlockConfig{ROPaths: []string{"/"}}); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile("/proc/self/uid_map", os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			t.Fatal("Landlock permitted a write outside the writable paths")
		}
		if !os.IsPermission(err) {
			t.Fatal(err)
		}
		return
	}
	if _, ok := LandlockStatus(); !ok {
		t.Skip("Landlock unavailable")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockProcWriteDenied$")
	cmd.Env = append(os.Environ(), "USH_TEST_LANDLOCK_PROC=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
}

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
