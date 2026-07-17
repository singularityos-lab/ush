// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package raven implements a userspace VFS with copy-on-write overlay
// semantics: it loads layers from the real filesystem and offers overlay-style
// read/write/delete operations entirely in userspace, without kernel overlayfs.
package raven

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// VFSInode represents a node in the userspace VFS.
type VFSInode struct {
	ino      uint64
	name     string
	isDir    bool
	mode     fs.FileMode
	uid, gid uint32
	size     int64
	mtime    time.Time
	content  []byte
	children []*VFSInode
	xattrs   map[string][]byte
	mu       sync.RWMutex
}

// LayerVFS is a userspace VFS with multi-layer COW semantics.
// Layers are searched from upper (writable) down to lower (read-only).
// Whiteout files (.wh.*) mask files in lower layers.
type LayerVFS struct {
	layers  []*vfsLayer
	mu      sync.RWMutex
	nextIno uint64
}

type vfsLayer struct {
	root     *VFSInode
	readOnly bool
	name     string
}

// NewLayerVFS creates a VFS with specified lower (read-only) and upper (writable) layers.
func NewLayerVFS(lowerDirs []string, upperDir string) (*LayerVFS, error) {
	v := &LayerVFS{nextIno: 2}

	for _, dir := range lowerDirs {
		layer := &vfsLayer{name: dir, readOnly: true}
		root, err := v.loadDirFromHost(dir)
		if err != nil {
			return nil, fmt.Errorf("loading layer %s: %w", dir, err)
		}
		layer.root = root
		v.layers = append(v.layers, layer)
	}

	upper := &vfsLayer{name: upperDir, readOnly: false}
	if _, err := os.Stat(upperDir); err == nil {
		root, err := v.loadDirFromHost(upperDir)
		if err != nil {
			return nil, fmt.Errorf("loading upper layer: %w", err)
		}
		upper.root = root
	} else {
		upper.root = &VFSInode{
			ino: v.allocIno(), isDir: true, name: "/",
			mode: 0o755, mtime: time.Now(),
		}
	}
	v.layers = append(v.layers, upper)

	return v, nil
}

// Stat returns file info for path, searching layers from upper to lower.
func (v *LayerVFS) Stat(path string) (fs.FileInfo, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.isWhiteout(path) {
		return nil, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
	}

	for i := len(v.layers) - 1; i >= 0; i-- {
		if node := v.findNode(v.layers[i].root, path); node != nil {
			return &vfsFileInfo{node: node, path: path}, nil
		}
	}

	return nil, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
}

// ReadFile reads a file from the composed filesystem.
func (v *LayerVFS) ReadFile(path string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.isWhiteout(path) {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}

	for i := len(v.layers) - 1; i >= 0; i-- {
		if node := v.findNode(v.layers[i].root, path); node != nil {
			if node.isDir {
				return nil, fmt.Errorf("%s is a directory", path)
			}
			return node.content, nil
		}
	}

	return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
}

// WriteFile writes a file to the upper (writable) layer.
func (v *LayerVFS) WriteFile(path string, data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	upper := v.layers[len(v.layers)-1]
	if upper.readOnly {
		return fmt.Errorf("upper layer is read-only")
	}

	return v.writeNode(upper.root, path, data)
}

// Remove removes a file by creating a whiteout in the upper layer.
func (v *LayerVFS) Remove(path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	upper := v.layers[len(v.layers)-1]
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	whiteoutPath := filepath.Join(dir, ".wh."+base)
	return v.writeNode(upper.root, whiteoutPath, []byte{})
}

// ListDir lists directory contents with COW merge across layers.
func (v *LayerVFS) ListDir(path string) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	seen := map[string]bool{}
	var entries []string

	for i := len(v.layers) - 1; i >= 0; i-- {
		node := v.findNode(v.layers[i].root, path)
		if node == nil || !node.isDir {
			continue
		}
		for _, child := range node.children {
			if strings.HasPrefix(child.name, ".wh.") {
				masked := strings.TrimPrefix(child.name, ".wh.")
				seen[masked] = true
				continue
			}
			if !seen[child.name] {
				entries = append(entries, child.name)
				seen[child.name] = true
			}
		}
	}

	return entries, nil
}

func (v *LayerVFS) isWhiteout(path string) bool {
	upper := v.layers[len(v.layers)-1]
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	whiteoutPath := filepath.Join(dir, ".wh."+base)
	return v.findNode(upper.root, whiteoutPath) != nil
}

func (v *LayerVFS) findNode(root *VFSInode, path string) *VFSInode {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := root
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if !current.isDir {
			return nil
		}
		found := false
		for _, child := range current.children {
			if child.name == part {
				current = child
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return current
}

func (v *LayerVFS) writeNode(root *VFSInode, path string, data []byte) error {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := root
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == len(parts)-1 {
			for _, child := range current.children {
				if child.name == part {
					child.content = data
					child.size = int64(len(data))
					child.mtime = time.Now()
					return nil
				}
			}
			node := &VFSInode{
				ino: v.allocIno(), name: part, isDir: false,
				mode: 0o644, mtime: time.Now(),
				content: data, size: int64(len(data)),
			}
			current.children = append(current.children, node)
			return nil
		}
		found := false
		for _, child := range current.children {
			if child.name == part && child.isDir {
				current = child
				found = true
				break
			}
		}
		if !found {
			dir := &VFSInode{
				ino: v.allocIno(), name: part, isDir: true,
				mode: 0o755, mtime: time.Now(),
			}
			current.children = append(current.children, dir)
			current = dir
		}
	}
	return nil
}

func (v *LayerVFS) loadDirFromHost(dir string) (*VFSInode, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}

	root := &VFSInode{
		ino:   v.allocIno(),
		name:  "/",
		isDir: info.IsDir(),
		mode:  info.Mode(),
		mtime: info.ModTime(),
		size:  info.Size(),
	}

	if !info.IsDir() {
		return root, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		childPath := filepath.Join(dir, entry.Name())
		childInfo, err := entry.Info()
		if err != nil {
			continue
		}

		child := &VFSInode{
			ino:   v.allocIno(),
			name:  entry.Name(),
			isDir: entry.IsDir(),
			mode:  childInfo.Mode(),
			mtime: childInfo.ModTime(),
			size:  childInfo.Size(),
		}

		if !entry.IsDir() && childInfo.Size() <= 64*1024 {
			if data, err := os.ReadFile(childPath); err == nil {
				child.content = data
			}
		}

		root.children = append(root.children, child)
	}

	return root, nil
}

func (v *LayerVFS) allocIno() uint64 {
	v.nextIno++
	return v.nextIno
}

type vfsFileInfo struct {
	node *VFSInode
	path string
}

func (fi *vfsFileInfo) Name() string       { return filepath.Base(fi.path) }
func (fi *vfsFileInfo) Size() int64        { return fi.node.size }
func (fi *vfsFileInfo) Mode() fs.FileMode  { return fi.node.mode }
func (fi *vfsFileInfo) ModTime() time.Time { return fi.node.mtime }
func (fi *vfsFileInfo) IsDir() bool        { return fi.node.isDir }
func (fi *vfsFileInfo) Sys() any           { return nil }

// Integrity helpers for the Singularity Guard.
//
// The integrity monitor (singd) detects when a ush layer shadows or diverges
// from an immutable system file; raven already understands layer semantics.

// HashLayer walks a layer directory and returns a map of guest-absolute path
// (e.g. "/usr/bin/foo") to the SHA-256 (hex) of the file's contents. Symlinks,
// whiteouts (.wh.*) and non-regular files are skipped.
func HashLayer(dir string) (map[string]string, error) {
	out := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), ".wh.") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		sum, err := sha256File(path)
		if err != nil {
			return nil
		}
		out["/"+filepath.ToSlash(rel)] = sum
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BaselineDiff reports how a layer relates to the signed system baseline.
type BaselineDiff struct {
	// Shadowed: layer files whose path also exists in the baseline, the layer
	// overrides an immutable system file (a classic persistence technique).
	Shadowed []string `json:"shadowed"`
	// Modified: shadowed paths whose content hash differs from the baseline.
	Modified []string `json:"modified"`
	// New: layer files with no counterpart in the baseline.
	New []string `json:"new"`
}

type signedBaseline struct {
	Files map[string]string `json:"files"`
}

// DiffAgainstBaseline hashes layerDir and compares it to the baseline JSON
// produced at OS build time (/etc/singularity/baseline.json). The caller must
// verify the baseline signature before trusting it; this function only
// computes the set difference (shadowed / modified / new).
func DiffAgainstBaseline(layerDir, baselinePath string) (*BaselineDiff, error) {
	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var base signedBaseline
	if err := json.Unmarshal(raw, &base); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}

	layer, err := HashLayer(layerDir)
	if err != nil {
		return nil, err
	}

	diff := &BaselineDiff{}
	for path, sum := range layer {
		if baseSum, ok := base.Files[path]; ok {
			diff.Shadowed = append(diff.Shadowed, path)
			if baseSum != sum {
				diff.Modified = append(diff.Modified, path)
			}
		} else {
			diff.New = append(diff.New, path)
		}
	}
	sort.Strings(diff.Shadowed)
	sort.Strings(diff.Modified)
	sort.Strings(diff.New)
	return diff, nil
}
