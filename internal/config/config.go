// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package config manages ush configuration.
// The format is JSON; the file lives in ~/.config/ush/config.json.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const (
	AppName    = "ush"
	AppVersion = "0.1.0"
)

// Config is the main configuration structure for ush.
type Config struct {
	// StorageDir is the directory where layers, audit logs, and sessions live.
	// Default: ~/.local/share/ush
	StorageDir string `json:"storage_dir,omitempty"`

	// FallbackShell is the shell to use as fallback during development.
	// Default: /bin/bash
	FallbackShell string `json:"fallback_shell,omitempty"`

	// BrokerBusName is the D-Bus name of the host-side broker.
	BrokerBusName string `json:"broker_bus_name,omitempty"`

	// NetworkBackend is the network backend (pasta, passt).
	NetworkBackend string `json:"network_backend,omitempty"`

	// OverlayBackend is the filesystem backend (kernel, fuse).
	OverlayBackend string `json:"overlay_backend,omitempty"`

	// EnablePIDNamespace enables the PID namespace (default: true).
	EnablePIDNamespace bool `json:"enable_pid_namespace"`

	// EnableNetNamespace enables the network namespace (default: true).
	EnableNetNamespace bool `json:"enable_net_namespace"`

	// ExtraBindMounts are additional bind mounts (host_path:guest_path[:ro]).
	ExtraBindMounts []string `json:"extra_bind_mounts,omitempty"`

	// LogLevel is the log level (debug, info, warn, error).
	LogLevel string `json:"log_level,omitempty"`

	// PermissionMode controls how the broker asks for permission.
	//   "simple" (default): per-app prompts. Network just works (the host is
	//       protected structurally), and only sensitive capabilities (camera,
	//       microphone, ...) prompt, once per app.
	//   "fine": power-user / red-team. Every connect()/device/mount is mediated
	//       and prompted individually.
	PermissionMode string `json:"permission_mode,omitempty"`
}

// Defaults returns the default configuration.
func Defaults() *Config {
	return &Config{
		StorageDir:         defaultStorageDir(),
		FallbackShell:      "/bin/bash",
		BrokerBusName:      "io.github.singularityos_lab.ush.Broker",
		NetworkBackend:     "pasta",
		OverlayBackend:     "kernel",
		EnablePIDNamespace: true,
		EnableNetNamespace: true,
		// The logger writes to the user's terminal, so anything above error puts
		// internal JSON in the middle of ordinary commands. "info" here also
		// silently defeated the quiet-unless-verbose default in cmd/ush: every
		// user gets this value, so the else-if that honours a configured level
		// always fired. -v still selects info.
		LogLevel: "error",
	}
}

// Load loads the configuration from disk, applying defaults for missing fields.
func Load() (*Config, error) {
	cfg := Defaults()
	path := configPath()

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.applyDefaults()
	return cfg, nil
}

// Save writes the configuration to disk.
func (c *Config) Save() error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func (c *Config) applyDefaults() {
	d := Defaults()
	if c.StorageDir == "" {
		c.StorageDir = d.StorageDir
	}
	if c.FallbackShell == "" {
		c.FallbackShell = d.FallbackShell
	}
	if c.BrokerBusName == "" {
		c.BrokerBusName = d.BrokerBusName
	}
	if c.NetworkBackend == "" {
		c.NetworkBackend = d.NetworkBackend
	}
	if c.OverlayBackend == "" {
		c.OverlayBackend = d.OverlayBackend
	}
	if c.LogLevel == "" {
		c.LogLevel = d.LogLevel
	}
}

// StoragePath returns a sub-path under the storage directory.
func (c *Config) StoragePath(parts ...string) string {
	return filepath.Join(append([]string{c.StorageDir}, parts...)...)
}

func configPath() string {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(configHome, AppName, "config.json")
}

func defaultStorageDir() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}
	return filepath.Join(dataHome, AppName)
}
