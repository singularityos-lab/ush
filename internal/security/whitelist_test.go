// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWhitelistBuild(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	os.MkdirAll(binDir, 0755)

	os.WriteFile(filepath.Join(binDir, "ls"), []byte("#!/bin/sh"), 0755)
	os.WriteFile(filepath.Join(binDir, "cat"), []byte("#!/bin/sh"), 0755)
	os.WriteFile(filepath.Join(binDir, "README"), []byte("not executable"), 0644)

	w := NewExecWhitelist()
	if err := w.BuildFromRoot(root); err != nil {
		t.Fatalf("BuildFromRoot: %v", err)
	}

	if w.Count() != 2 {
		t.Errorf("Count = %d, want 2 (only executables)", w.Count())
	}
}

func TestWhitelistAllowInodeMatch(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	os.MkdirAll(binDir, 0755)

	binPath := filepath.Join(binDir, "ls")
	os.WriteFile(binPath, []byte("#!/bin/sh\necho hello"), 0755)

	w := NewExecWhitelist()
	if err := w.BuildFromRoot(root); err != nil {
		t.Fatalf("BuildFromRoot: %v", err)
	}

	hostPath := binPath
	guestPath := "/usr/bin/ls"

	if !w.Allow(hostPath, guestPath) {
		t.Error("Allow should return true for whitelisted file with matching inode")
	}
}

func TestWhitelistAllowInodeMismatch(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	os.MkdirAll(binDir, 0755)

	originalPath := filepath.Join(binDir, "ls")
	os.WriteFile(originalPath, []byte("#!/bin/sh\necho original"), 0755)

	w := NewExecWhitelist()
	w.BuildFromRoot(root)

	replacedPath := filepath.Join(binDir, "ls.replaced")
	os.WriteFile(replacedPath, []byte("#!/bin/sh\necho replaced"), 0755)

	if w.Allow(replacedPath, "/usr/bin/ls") {
		t.Error("Allow should return false for file with different inode")
	}
}

func TestWhitelistSkipMutable(t *testing.T) {
	root := t.TempDir()

	for _, d := range []string{"home/user", "tmp", "run", "proc", "sys", "dev"} {
		fullDir := filepath.Join(root, d)
		os.MkdirAll(fullDir, 0755)
		os.WriteFile(filepath.Join(fullDir, "malicious"), []byte("#!/bin/sh"), 0755)
	}

	w := NewExecWhitelist()
	w.BuildFromRoot(root)

	if w.Count() != 0 {
		t.Errorf("Count = %d, want 0 (mutable dirs should be skipped)", w.Count())
	}
}

func TestWhitelistAddFile(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "custom-bin")
	os.WriteFile(binPath, []byte("#!/bin/sh"), 0755)

	w := NewExecWhitelist()
	if err := w.AddFile(binPath, "/usr/local/bin/custom-bin"); err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	if w.Count() != 1 {
		t.Errorf("Count = %d, want 1", w.Count())
	}
}

func TestWhitelistAddDir(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	os.MkdirAll(binDir, 0755)
	os.WriteFile(filepath.Join(binDir, "app1"), []byte("#!/bin/sh"), 0755)
	os.WriteFile(filepath.Join(binDir, "app2"), []byte("#!/bin/sh"), 0755)
	os.WriteFile(filepath.Join(binDir, "data.txt"), []byte("not exec"), 0644)

	w := NewExecWhitelist()
	if err := w.AddDir(binDir, "/opt/bin"); err != nil {
		t.Fatalf("AddDir: %v", err)
	}

	if w.Count() != 2 {
		t.Errorf("Count = %d, want 2", w.Count())
	}
}

func TestFileID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testfile")
	os.WriteFile(path, []byte("content"), 0644)

	fid, err := fileID(path)
	if err != nil {
		t.Fatalf("fileID: %v", err)
	}

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		t.Fatalf("stat: %v", err)
	}

	if fid.Dev != stat.Dev || fid.Ino != stat.Ino {
		t.Errorf("fileID = {Dev:%d, Ino:%d}, want {Dev:%d, Ino:%d}", fid.Dev, fid.Ino, stat.Dev, stat.Ino)
	}
}

func TestShouldSkipForWhitelist(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/home/user/script", true},
		{"/tmp/malicious", true},
		{"/run/ush/exec/apt-get", true},
		{"/proc/self/exe", true},
		{"/sys/kernel", true},
		{"/dev/null", true},
		{"/usr/bin/ls", false},
		{"/bin/sh", false},
		{"/usr/local/bin/custom", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := ShouldSkipForWhitelist(tt.path)
			if got != tt.want {
				t.Errorf("ShouldSkipForWhitelist(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
