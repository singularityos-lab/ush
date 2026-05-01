// SPDX-License-Identifier: GPL-3.0-or-later

package preload

import (
	"strings"
	"testing"
)

func TestDpkgShimDoesNotSuppressMissingFiles(t *testing.T) {
	start := strings.Index(DpkgShimC, "static int is_ro_error")
	if start < 0 {
		t.Fatal("is_ro_error not found")
	}
	end := strings.Index(DpkgShimC[start:], "\n}")
	if end < 0 {
		t.Fatal("is_ro_error end not found")
	}
	body := DpkgShimC[start : start+end]
	returnStart := strings.Index(body, "return ")
	if returnStart < 0 {
		t.Fatal("is_ro_error return not found")
	}
	returnLineEnd := strings.Index(body[returnStart:], ";")
	if returnLineEnd < 0 {
		t.Fatal("is_ro_error return end not found")
	}
	returnLine := body[returnStart : returnStart+returnLineEnd]

	if strings.Contains(returnLine, "ENOENT") {
		t.Fatal("is_ro_error must not suppress ENOENT")
	}
}
