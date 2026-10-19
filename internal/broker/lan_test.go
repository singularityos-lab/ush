package broker

import (
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/ush/internal/policy"
)

func TestLanSharing(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	status := func() bool { return srv.dispatch(rpcRequest{Method: "LanStatus"}).Trusted }
	onDisk := func() bool {
		eng, err := policy.NewEngine(filepath.Join(dir, "policy.json"))
		if err != nil {
			t.Fatal(err)
		}
		return policy.LanShared(eng)
	}

	srv.auto = &autoDecider{enabled: true, confirm: false}
	if resp := srv.dispatch(rpcRequest{Method: "AllowLan"}); resp.Error == "" {
		t.Error("AllowLan without confirmation should fail")
	}
	if status() || onDisk() {
		t.Fatal("lan shared after a refused confirmation")
	}

	srv.auto = &autoDecider{enabled: true, confirm: true}
	if resp := srv.dispatch(rpcRequest{Method: "AllowLan"}); resp.Error != "" {
		t.Fatal(resp.Error)
	}
	if !status() || !onDisk() {
		t.Fatal("lan not shared after AllowLan")
	}

	if resp := srv.dispatch(rpcRequest{Method: "DenyLan"}); resp.Error != "" {
		t.Fatal(resp.Error)
	}
	if status() || onDisk() {
		t.Fatal("lan still shared after DenyLan")
	}
}
