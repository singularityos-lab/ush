package pkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMoveAsideUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write any file")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "term.log")
	open := filepath.Join(dir, "history.log")
	os.WriteFile(locked, []byte("x"), 0o400)
	os.WriteFile(open, []byte("y"), 0o644)
	moveAsideUnwritable(dir, "term.log", "history.log", "missing.log")
	if _, err := os.Stat(locked); !os.IsNotExist(err) {
		t.Error("unwritable log was not moved aside")
	}
	if _, err := os.Stat(locked + ".unwritable"); err != nil {
		t.Error("moved log is missing")
	}
	if _, err := os.Stat(open); err != nil {
		t.Error("writable log must stay in place")
	}
}
