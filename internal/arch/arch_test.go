// SPDX-License-Identifier: GPL-3.0-or-later

package arch

import (
	"runtime"
	"testing"
)

func TestRunningArchIsKnown(t *testing.T) {
	if Debian() == "" || Triplet() == "" {
		t.Fatalf("no Debian names for %s", runtime.GOARCH)
	}
}

func TestDebianFor(t *testing.T) {
	for goarch, want := range map[string]string{"amd64": "amd64", "arm64": "arm64"} {
		got, err := DebianFor(goarch)
		if err != nil || got != want {
			t.Errorf("DebianFor(%q) = %q, %v; want %q", goarch, got, err, want)
		}
	}
	if _, err := DebianFor("riscv64"); err == nil {
		t.Error("DebianFor(riscv64) should fail")
	}
}
