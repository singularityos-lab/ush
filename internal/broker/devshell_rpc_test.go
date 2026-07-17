// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"os"
	"path/filepath"
	"testing"
)

// The dsh opt-in must be written and read through the broker's own storage dir.
// This is the whole point of routing `ush dsh enable` through the broker: when
// the CLI runs inside the sandbox, only the broker can reach the host storage
// where the dsh gate actually looks.
func TestDevShellRPCRoundTripHitsServerStorage(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(dir)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	// Starts not-enabled.
	if resp := srv.dispatch(rpcRequest{Method: "DevShellStatus"}); resp.Enabled {
		t.Fatalf("fresh store: Enabled = true, want false")
	}

	// Enable through the RPC.
	if resp := srv.dispatch(rpcRequest{Method: "SetDevShellEnabled", Enable: true}); resp.Error != "" {
		t.Fatalf("SetDevShellEnabled: %s", resp.Error)
	}

	// The marker must land in the server's storage dir, not anywhere else.
	if _, err := os.Stat(filepath.Join(dir, "dsh-opt-in")); err != nil {
		t.Fatalf("opt-in marker not in server storage: %v", err)
	}

	// And status must now report enabled.
	if resp := srv.dispatch(rpcRequest{Method: "DevShellStatus"}); !resp.Enabled {
		t.Fatalf("after enable: Enabled = false, want true")
	}

	// Disable clears it again.
	if resp := srv.dispatch(rpcRequest{Method: "SetDevShellEnabled", Enable: false}); resp.Error != "" {
		t.Fatalf("SetDevShellEnabled(false): %s", resp.Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "dsh-opt-in")); !os.IsNotExist(err) {
		t.Fatalf("marker still present after disable: %v", err)
	}
}
