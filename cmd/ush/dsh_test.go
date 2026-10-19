package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDshArgs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "become-dsh")
	os.WriteFile(p, []byte(`["-c","make test"]`), 0o600)
	if got, ok := dshArgs(p); !ok || !reflect.DeepEqual(got, []string{"-c", "make test"}) {
		t.Errorf("dshArgs = %v, %v", got, ok)
	}
	os.WriteFile(p, []byte(`[]`), 0o600)
	if got, ok := dshArgs(p); !ok || len(got) != 0 {
		t.Errorf("empty dshArgs = %v, %v", got, ok)
	}
	os.WriteFile(p, []byte("1\n"), 0o600)
	if _, ok := dshArgs(p); ok {
		t.Error("legacy sentinel must fall back to the original arguments")
	}
}
