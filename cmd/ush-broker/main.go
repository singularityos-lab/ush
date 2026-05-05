// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// ush-broker - host-side service for the ush permission broker.
// Runs as a user systemd unit on the host and handles permission
// requests coming from the guest via D-Bus.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/singularityos-lab/ush/internal/broker"
	"github.com/singularityos-lab/ush/internal/config"
	ushlog "github.com/singularityos-lab/ush/internal/log"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ush-broker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ushlog.Init(cfg.LogLevel, nil)
	ushlog.Info("ush-broker: starting", "version", config.AppVersion)

	storageDir := filepath.Join(cfg.StorageDir)
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return fmt.Errorf("storage: %w", err)
	}

	srv, err := broker.NewServer(storageDir)
	if err != nil {
		return fmt.Errorf("broker server: %w", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("broker start: %w", err)
	}
	defer srv.Stop()

	// Host-only management interface on the session bus (for the desktop
	// portal/shell to trust apps). Best-effort; the socket transport is primary.
	srv.StartManagementBus()

	// Wait for termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	ushlog.Info("ush-broker: shutting down", "signal", sig)
	return nil
}
