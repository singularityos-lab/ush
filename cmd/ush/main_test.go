// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "testing"

func TestGuestStartDirKeepsCwdInsideHome(t *testing.T) {
	got := guestStartDir("/home/user", "/home/user/Projects/app")
	if got != "/home/user/Projects/app" {
		t.Fatalf("guestStartDir = %q, want cwd inside home", got)
	}
}

func TestGuestStartDirFallsBackToHomeOutsideHome(t *testing.T) {
	got := guestStartDir("/home/user", "/etc")
	if got != "/home/user" {
		t.Fatalf("guestStartDir = %q, want home", got)
	}
}

func TestGuestStartDirDoesNotAcceptPrefixSibling(t *testing.T) {
	got := guestStartDir("/home/user", "/home/user-other/project")
	if got != "/home/user" {
		t.Fatalf("guestStartDir = %q, want home", got)
	}
}

func TestGuestStartDirHomeRoot(t *testing.T) {
	got := guestStartDir("/home/user", "/home/user")
	if got != "/home/user" {
		t.Fatalf("guestStartDir = %q, want home", got)
	}
}
