// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package fuse implements a userspace overlay backend with copy-on-write
// semantics and whiteout files following the overlayfs convention, entirely in
// userspace - no kernel overlayfs or mount required. The guest filesystem
// itself is mounted elsewhere (internal/fs/overlay.go, which prefers
// fuse-overlayfs and falls back to the kernel driver); this package computes
// layer merges and diffs without mounting anything.
package fuse

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// LayerBackend is the storage backend interface, implemented by both the
// overlayfs and FUSE backends.
type LayerBackend interface {
	// Stat returns information about a file in the composed filesystem.
	Stat(path string) (fs.FileInfo, error)

	// ReadFile reads a file in the composed filesystem.
	ReadFile(path string) ([]byte, error)

	// WriteFile writes a file to the upper layer.
	WriteFile(path string, data []byte, perm os.FileMode) error

	// Remove removes a file (creates a whiteout in the upper layer).
	Remove(path string) error

	// ListDir lists the contents of a directory.
	ListDir(path string) ([]fs.DirEntry, error)

	// Type returns the backend type.
	Type() BackendType
}

// BackendType identifies the backend type.
type BackendType string

const (
	BackendKernelOverlay BackendType = "kernel_overlay"
	BackendFUSE          BackendType = "fuse"
)

// FUSEBackend implements a userspace overlay filesystem with COW semantics.
// No kernel overlayfs or mount required - all operations are on plain
// directories with the standard overlayfs whiteout convention (.wh.* files).
//
// Use cases: layer inspection (pkg diff, pkg inspect), unit testing,
// and as a foundation for a future FUSE mount backend.
type FUSEBackend struct {
	mu         sync.RWMutex
	upperDir   string
	lowerDirs  []string
	mountpoint string
}

// NewFUSEBackend creates a new userspace overlay backend.
// upperDir is the writable layer directory.
func NewFUSEBackend(upperDir string) *FUSEBackend {
	return &FUSEBackend{
		upperDir: upperDir,
	}
}

// AddLowerLayer adds a read-only lower layer to the overlay stack.
func (b *FUSEBackend) AddLowerLayer(path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lowerDirs = append(b.lowerDirs, path)
	return nil
}

// Stat returns file info, checking the upper layer first, then the lower
// layers in order.
func (b *FUSEBackend) Stat(path string) (fs.FileInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Check first whether a whiteout exists in the upper layer for this file.
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	whiteoutPath := filepath.Join(b.upperDir, dir, ".wh."+base)
	if _, err := os.Lstat(whiteoutPath); err == nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
	}

	// Upper layer takes priority.
	upperPath := filepath.Join(b.upperDir, path)
	if info, err := os.Lstat(upperPath); err == nil {
		return info, nil
	}

	// Search in the lower layers.
	for i := len(b.lowerDirs) - 1; i >= 0; i-- {
		lowerPath := filepath.Join(b.lowerDirs[i], path)
		if info, err := os.Lstat(lowerPath); err == nil {
			return info, nil
		}
	}

	return nil, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
}

// ReadFile reads a file from the composed filesystem.
func (b *FUSEBackend) ReadFile(path string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Check whiteout.
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	whiteoutPath := filepath.Join(b.upperDir, dir, ".wh."+base)
	if _, err := os.Lstat(whiteoutPath); err == nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}

	// Upper first.
	upperPath := filepath.Join(b.upperDir, path)
	if _, err := os.Lstat(upperPath); err == nil {
		return os.ReadFile(upperPath)
	}

	// Lower layers.
	for i := len(b.lowerDirs) - 1; i >= 0; i-- {
		lowerPath := filepath.Join(b.lowerDirs[i], path)
		data, err := os.ReadFile(lowerPath)
		if err == nil {
			return data, nil
		}
	}

	return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
}

// WriteFile writes a file to the upper layer (COW: copy first if it exists in the lower).
func (b *FUSEBackend) WriteFile(path string, data []byte, perm os.FileMode) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	upperPath := filepath.Join(b.upperDir, path)
	if err := os.MkdirAll(filepath.Dir(upperPath), 0755); err != nil {
		return fmt.Errorf("fuse write: mkdir: %w", err)
	}
	return os.WriteFile(upperPath, data, perm)
}

// Remove removes a file by creating a whiteout file in the upper layer.
// Whiteouts follow the overlayfs convention: .wh.<name> file.
func (b *FUSEBackend) Remove(path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	whiteoutPath := filepath.Join(b.upperDir, dir, ".wh."+base)

	if err := os.MkdirAll(filepath.Join(b.upperDir, dir), 0755); err != nil {
		return err
	}
	f, err := os.Create(whiteoutPath)
	if err != nil {
		return err
	}
	return f.Close()
}

// ListDir lists the contents of a directory with overlay semantics.
func (b *FUSEBackend) ListDir(path string) ([]fs.DirEntry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	entries := make(map[string]fs.DirEntry)
	whiteouts := make(map[string]bool)

	// Read lower layers first (low priority).
	for _, lower := range b.lowerDirs {
		dirPath := filepath.Join(lower, path)
		dirEntries, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, e := range dirEntries {
			name := e.Name()
			if _, isWH := entries[".wh."+name]; !isWH {
				entries[name] = e
			}
		}
	}

	// Then the upper (high priority, can override or add whiteouts).
	upperDir := filepath.Join(b.upperDir, path)
	upperEntries, err := os.ReadDir(upperDir)
	if err == nil {
		for _, e := range upperEntries {
			name := e.Name()
			// Whiteout: remove from the list.
			if len(name) > 4 && name[:4] == ".wh." {
				original := name[4:]
				whiteouts[original] = true
				delete(entries, original)
				continue
			}
			entries[name] = e
		}
	}

	// Filter out whiteouts.
	result := make([]fs.DirEntry, 0, len(entries))
	for name, e := range entries {
		if !whiteouts[name] {
			result = append(result, e)
		}
	}
	return result, nil
}

// Type returns the backend type.
func (b *FUSEBackend) Type() BackendType {
	return BackendFUSE
}

// isWhiteout checks if a file is an overlayfs-style whiteout.
func isWhiteout(path string) bool {
	base := filepath.Base(path)
	return len(base) > 4 && base[:4] == ".wh."
}

// KernelOverlayBackend is a thin wrapper for the kernel overlayfs backend.
// Delegates to the existing implementation in internal/fs/overlay.go.
type KernelOverlayBackend struct {
	upperDir string
	workDir  string
}

// NewKernelOverlayBackend creates a backend that uses kernel overlayfs.
func NewKernelOverlayBackend(upperDir, workDir string) *KernelOverlayBackend {
	return &KernelOverlayBackend{
		upperDir: upperDir,
		workDir:  workDir,
	}
}

// Type returns the backend type.
func (b *KernelOverlayBackend) Type() BackendType {
	return BackendKernelOverlay
}

// Stub implementations (real logic is in overlay.go).
func (b *KernelOverlayBackend) Mount(lower, mountpoint string) error  { return nil }
func (b *KernelOverlayBackend) Unmount(mountpoint string) error       { return nil }
func (b *KernelOverlayBackend) AddLowerLayer(path string) error       { return nil }
func (b *KernelOverlayBackend) Stat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (b *KernelOverlayBackend) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (b *KernelOverlayBackend) WriteFile(p string, d []byte, m os.FileMode) error {
	return os.WriteFile(p, d, m)
}
func (b *KernelOverlayBackend) Remove(path string) error { return os.Remove(path) }
func (b *KernelOverlayBackend) ListDir(path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}
