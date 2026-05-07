// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package devpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// redirect points the image/managed policy paths at a temp dir for the test and
// returns the dir. Missing files mean "no policy declared".
func redirect(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	imagePolicyPath = filepath.Join(dir, "image-policy")
	managedPolicyPath = filepath.Join(dir, "managed-policy")
	return dir
}

func writePolicy(t *testing.T, path string, p Policy) {
	t.Helper()
	if err := os.WriteFile(path, []byte(string(p)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultIsOptInOff(t *testing.T) {
	redirect(t) // no policy files written -> default OptIn
	store := t.TempDir()
	if got := Evaluate(store); got != DenyNotEnabled {
		t.Errorf("default Evaluate = %v, want DenyNotEnabled", got)
	}
	if !Permitted() {
		t.Error("default Permitted = false, want true")
	}
}

func TestUserOptInFlow(t *testing.T) {
	redirect(t)
	store := t.TempDir()
	if err := SetUserEnabled(store, true); err != nil {
		t.Fatal(err)
	}
	if got := Evaluate(store); got != Allow {
		t.Errorf("after enable, Evaluate = %v, want Allow", got)
	}
	if err := SetUserEnabled(store, false); err != nil {
		t.Fatal(err)
	}
	if got := Evaluate(store); got != DenyNotEnabled {
		t.Errorf("after disable, Evaluate = %v, want DenyNotEnabled", got)
	}
}

func TestImageForbiddenWins(t *testing.T) {
	dir := redirect(t)
	writePolicy(t, filepath.Join(dir, "image-policy"), Forbidden)
	store := t.TempDir()

	// Even an existing user opt-in must not enable a forbidden image.
	if err := os.WriteFile(filepath.Join(store, optInFile), []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := Evaluate(store); got != DenyForbidden {
		t.Errorf("forbidden Evaluate = %v, want DenyForbidden", got)
	}
	if Permitted() {
		t.Error("forbidden Permitted = true, want false")
	}
	if err := SetUserEnabled(store, true); err == nil {
		t.Error("SetUserEnabled should refuse under a forbidden policy")
	}
}

func TestImageEnabledNeedsNoOptIn(t *testing.T) {
	dir := redirect(t)
	writePolicy(t, filepath.Join(dir, "image-policy"), Enabled)
	if got := Evaluate(t.TempDir()); got != Allow {
		t.Errorf("enabled Evaluate = %v, want Allow", got)
	}
}

func TestManagedOverridesImage(t *testing.T) {
	dir := redirect(t)
	writePolicy(t, filepath.Join(dir, "image-policy"), OptIn)
	writePolicy(t, filepath.Join(dir, "managed-policy"), Forbidden)
	if got := Evaluate(t.TempDir()); got != DenyForbidden {
		t.Errorf("managed override Evaluate = %v, want DenyForbidden", got)
	}
}
