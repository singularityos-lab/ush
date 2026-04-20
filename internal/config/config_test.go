// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.FallbackShell != "/bin/bash" {
		t.Errorf("FallbackShell = %q, want /bin/bash", cfg.FallbackShell)
	}
	if cfg.BrokerBusName == "" {
		t.Error("BrokerBusName is empty")
	}
	if cfg.OverlayBackend != "kernel" {
		t.Errorf("OverlayBackend = %q, want kernel", cfg.OverlayBackend)
	}
	if !cfg.EnablePIDNamespace {
		t.Error("EnablePIDNamespace should be true by default")
	}
	if !cfg.EnableNetNamespace {
		t.Error("EnableNetNamespace should be true by default")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Setenv("HOME", dir)
	defer os.Unsetenv("XDG_CONFIG_HOME")

	cfg := Defaults()
	cfg.LogLevel = "debug"
	cfg.ExtraBindMounts = []string{"/opt:/opt:ro"}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", loaded.LogLevel)
	}
	if len(loaded.ExtraBindMounts) != 1 {
		t.Errorf("ExtraBindMounts len = %d, want 1", len(loaded.ExtraBindMounts))
	}
}

func TestStoragePath(t *testing.T) {
	cfg := Defaults()
	cfg.StorageDir = "/tmp/ush-test"

	got := cfg.StoragePath("layers", "persistent")
	want := "/tmp/ush-test/layers/persistent"
	if got != want {
		t.Errorf("StoragePath = %q, want %q", got, want)
	}
}

func TestInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", dir)
	defer os.Unsetenv("XDG_CONFIG_HOME")

	cfgPath := filepath.Join(dir, AppName, "config.json")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	os.WriteFile(cfgPath, []byte("{invalid json}"), 0600)

	_, err := Load()
	if err == nil {
		t.Error("Load with invalid JSON should return an error")
	}
	var syntaxErr *json.SyntaxError
	if err == nil || syntaxErr != nil {
		// ok
	}
}
