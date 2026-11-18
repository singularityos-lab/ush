package broker_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/ush/internal/broker"
	"github.com/singularityos-lab/ush/internal/security"
)

func TestCpakConfinedClient(t *testing.T) {
	if os.Getenv("USH_TEST_CPAK_CONFINED") == "1" {
		if err := security.ApplyLandlock(security.LandlockConfig{ROPaths: []string{"/"}}); err != nil {
			t.Fatal(err)
		}
		if err := security.InstallSeccompFilter(); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile("/proc/self/uid_map", os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			t.Fatal("confined client can write uid_map")
		}
		if !os.IsPermission(err) {
			t.Fatal(err)
		}
		input, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		client, err := broker.NewClient("")
		if err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err = client.RunCpak(ctx, broker.CpakRequest{Operation: "doctor"}, input, &out, &stderr)
		if err != nil || !strings.Contains(out.String(), "[OK] unprivileged user namespaces:") {
			t.Fatalf("err=%v out=%q stderr=%q", err, out.String(), stderr.String())
		}
		f, err = os.OpenFile("/proc/self/uid_map", os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			t.Fatal("bridge changed the client confinement")
		}
		if !os.IsPermission(err) {
			t.Fatal(err)
		}
		return
	}
	if _, ok := security.LandlockStatus(); !ok {
		t.Skip("Landlock unavailable")
	}
	if _, err := os.Stat("/usr/bin/cpak"); err != nil {
		t.Skip("system cpak unavailable")
	}
	if err := exec.Command("unshare", "-Ur", "/bin/true").Run(); err != nil {
		t.Skipf("host namespaces unavailable: %v", err)
	}
	dir, err := os.MkdirTemp("", "cb-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("USH_BROKER_SOCK", filepath.Join(dir, "broker.sock"))
	t.Setenv("USH_BROKER_AUTO", "deny")
	t.Setenv("USH_BROKER_CONFIRM", "yes")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "no-bus"))
	srv, err := broker.NewServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCpakConfinedClient$")
	cmd.Env = append(os.Environ(), "USH_TEST_CPAK_CONFINED=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
}
