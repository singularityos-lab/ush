package shell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCpakUnsupportedOperationDoesNotRunLocalBinary(t *testing.T) {
	t.Setenv("USH_PROFILE", "user")
	var output bytes.Buffer
	sh, err := New(&Config{StorageDir: t.TempDir(), Stdout: &output, Stderr: &output})
	if err != nil {
		t.Fatal(err)
	}
	err = sh.RunScript(context.Background(), strings.NewReader("cpak run bottles --env=LD_PRELOAD=evil"), "test")
	if err == nil || !strings.Contains(output.String(), "supported:") {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}
