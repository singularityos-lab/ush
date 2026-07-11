package tools

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestExtractTarXZZst verifies the in-process xz and zstd decoders extract a real
// compressed tar (built with the host tools) without any external command.
func TestExtractTarXZZst(t *testing.T) {
	for _, tc := range []struct{ name, comp string }{{"data.tar.xz", "xz"}, {"data.tar.zst", "zstd"}} {
		if _, err := exec.LookPath(tc.comp); err != nil {
			t.Skipf("%s not on build host, skipping", tc.comp)
		}
		tmp := t.TempDir()
		src := filepath.Join(tmp, "src")
		_ = os.MkdirAll(src, 0o755)
		_ = os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi from "+tc.comp), 0o644)
		out, err := exec.Command("bash", "-c", "tar cf - -C "+src+" . | "+tc.comp).Output()
		if err != nil {
			t.Fatalf("build archive: %v", err)
		}
		dest := filepath.Join(tmp, "dest")
		_ = os.MkdirAll(dest, 0o755)
		if err := extractTar(tc.name, out, dest); err != nil {
			t.Fatalf("%s: extractTar: %v", tc.name, err)
		}
		b, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
		if err != nil {
			t.Fatalf("%s: read extracted: %v", tc.name, err)
		}
		if string(b) != "hi from "+tc.comp {
			t.Fatalf("%s: got %q", tc.name, b)
		}
	}
}
