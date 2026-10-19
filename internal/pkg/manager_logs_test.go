package pkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMoveAsideUnwritable(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "term.log")
	open := filepath.Join(dir, "history.log")
	os.WriteFile(locked, []byte("x"), 0o400)
	os.WriteFile(open, []byte("y"), 0o644)
	if f, err := os.OpenFile(locked, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Skip("this process can write read-only files")
	}
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
