package broker

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/singularityos-lab/ush/internal/policy"
)

func TestDevOnlyTrustedDirsStayOutOfUsh(t *testing.T) {
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	both, dev := t.TempDir(), t.TempDir()
	if err := srv.trustDirConfirmed(both); err != nil {
		t.Fatal(err)
	}
	if err := srv.trustDirAs(dev, policy.CategoryDevDirDev); err != nil {
		t.Fatal(err)
	}
	list := func(req rpcRequest) []string {
		var dirs []string
		if err := json.Unmarshal([]byte(srv.dispatch(req).Permissions), &dirs); err != nil {
			t.Fatal(err)
		}
		return dirs
	}
	if got := list(rpcRequest{Method: "ListDevDirs"}); !reflect.DeepEqual(got, []string{both}) {
		t.Errorf("ush list = %v, want [%s]", got, both)
	}
	if got := list(rpcRequest{Method: "ListDevDirs", Enable: true}); len(got) != 2 {
		t.Errorf("dsh list = %v, want both dirs", got)
	}
	if err := srv.untrustDir(dev); err != nil {
		t.Fatal(err)
	}
	if got := list(rpcRequest{Method: "ListDevDirs", Enable: true}); !reflect.DeepEqual(got, []string{both}) {
		t.Errorf("dsh list after untrust = %v, want [%s]", got, both)
	}
}

func TestSyncDevDirs(t *testing.T) {
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv.auto = &autoDecider{enabled: true, confirm: true}
	shared := t.TempDir()
	if err := srv.trustDirConfirmed(shared); err != nil {
		t.Fatal(err)
	}
	n, err := srv.syncDevDirs(true)
	if err != nil || n != 1 {
		t.Fatalf("syncDevDirs(dev) = %d, %v, want 1, nil", n, err)
	}
	if n, err := srv.syncDevDirs(true); err != nil || n != 0 {
		t.Errorf("second syncDevDirs(dev) = %d, %v, want 0, nil", n, err)
	}
	srv.auto = &autoDecider{enabled: true, confirm: false}
	devOnly := t.TempDir()
	if err := srv.trustDirAs(devOnly, policy.CategoryDevDirDev); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.syncDevDirs(false); err == nil {
		t.Error("syncDevDirs(ush) without confirmation should fail")
	}
}

func TestDevDirDBusMethods(t *testing.T) {
	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &dbusManager{s: srv}
	dir := t.TempDir()
	if derr := d.TrustDevDir(dir); derr != nil {
		t.Fatal(derr)
	}
	if ok, _ := d.IsDevDirTrusted(dir); !ok {
		t.Error("IsDevDirTrusted = false after TrustDevDir")
	}
	if ok, _ := d.IsDirTrusted(dir); ok {
		t.Error("a dev-only dir must not count as shared with ush")
	}
	if derr := d.UntrustDevDir(dir); derr != nil {
		t.Fatal(derr)
	}
	if ok, _ := d.IsDevDirTrusted(dir); ok {
		t.Error("IsDevDirTrusted = true after UntrustDevDir")
	}
}
