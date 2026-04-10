// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package fs - layer.go manages ush storage layers.
//
// Layer structure:
//
//	~/.local/share/ush/
//	├── layers/
//	│   ├── persistent/         # shared persistent layer
//	│   │   ├── etc/upper/
//	│   │   ├── etc/work/
//	│   │   ├── var/upper/
//	│   │   ├── var/work/
//	│   │   ├── usr_bin_upper/
//	│   │   └── usr_bin_work/
//	│   └── ephemeral/          # ephemeral layers per session / --one-time
//	│       └── <session-id>/
//	│           ├── upper/
//	│           └── work/
//	├── sessions/               # active session metadata
//	└── audit/                  # broker audit log
package fs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LayerType distinguishes persistent from ephemeral layers.
type LayerType string

const (
	LayerPersistent LayerType = "persistent"
	LayerEphemeral  LayerType = "ephemeral"
)

// Layer describes a storage layer.
type Layer struct {
	ID        string    `json:"id"`
	Type      LayerType `json:"type"`
	SessionID string    `json:"session_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// Packages installed in this layer.
	Packages []string `json:"packages,omitempty"`
	// Dir upper overlay.
	UpperDir string `json:"upper_dir"`
	WorkDir  string `json:"work_dir"`
}

// LayerManager manages ush storage layers.
type LayerManager struct {
	baseDir string
}

// NewLayerManager creates a new LayerManager.
func NewLayerManager(storageDir string) *LayerManager {
	return &LayerManager{baseDir: filepath.Join(storageDir, "layers")}
}

// EnsurePersistent creates and returns the persistent layer.
func (lm *LayerManager) EnsurePersistent() (*Layer, error) {
	l := &Layer{
		ID:        "persistent",
		Type:      LayerPersistent,
		CreatedAt: time.Now(),
		UpperDir:  filepath.Join(lm.baseDir, "persistent", "pkg", "upper"),
		WorkDir:   filepath.Join(lm.baseDir, "persistent", "pkg", "work"),
	}

	for _, d := range []string{l.UpperDir, l.WorkDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("layer: mkdir %s: %w", d, err)
		}
	}

	return l, nil
}

// NewEphemeral creates an ephemeral layer for a session.
func (lm *LayerManager) NewEphemeral(sessionID string) (*Layer, error) {
	l := &Layer{
		ID:        fmt.Sprintf("ephemeral-%s", sessionID),
		Type:      LayerEphemeral,
		SessionID: sessionID,
		CreatedAt: time.Now(),
		UpperDir:  filepath.Join(lm.baseDir, "ephemeral", sessionID, "upper"),
		WorkDir:   filepath.Join(lm.baseDir, "ephemeral", sessionID, "work"),
	}

	for _, d := range []string{l.UpperDir, l.WorkDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("layer: mkdir %s: %w", d, err)
		}
	}

	return l, nil
}

// RemoveEphemeral removes an ephemeral layer and all its files.
func (lm *LayerManager) RemoveEphemeral(sessionID string) error {
	dir := filepath.Join(lm.baseDir, "ephemeral", sessionID)
	return os.RemoveAll(dir)
}

// FreezeEphemeral promotes an ephemeral layer to persistent
// by copying files from the ephemeral upper to the persistent upper.
func (lm *LayerManager) FreezeEphemeral(sessionID string) error {
	ephemDir := filepath.Join(lm.baseDir, "ephemeral", sessionID, "upper")
	persistDir := filepath.Join(lm.baseDir, "persistent", "pkg", "upper")

	return copyDir(ephemDir, persistDir)
}

// AddPackage adds a package to the persistent layer manifest.
func (lm *LayerManager) AddPackage(pkg string) error {
	return lm.updateManifest(func(m *layerManifest) {
		for _, p := range m.Packages {
			if p == pkg {
				return
			}
		}
		m.Packages = append(m.Packages, pkg)
	})
}

// RemovePackage removes a package from the manifest.
func (lm *LayerManager) RemovePackage(pkg string) error {
	return lm.updateManifest(func(m *layerManifest) {
		filtered := m.Packages[:0]
		for _, p := range m.Packages {
			if p != pkg {
				filtered = append(filtered, p)
			}
		}
		m.Packages = filtered
	})
}

// ListPackages returns the packages installed in the persistent layer.
func (lm *LayerManager) ListPackages() ([]string, error) {
	m, err := lm.loadManifest()
	if err != nil {
		return nil, err
	}
	return m.Packages, nil
}

// PersistentUpper returns the path of the persistent pkg layer upper directory.
func (lm *LayerManager) PersistentUpper() string {
	return filepath.Join(lm.baseDir, "persistent", "pkg", "upper")
}

// PkgRootDir returns the directory used as dpkg's --instdir.
// Packages installed via pkg install land here; the shell adds
// the subpaths to PATH/LD_LIBRARY_PATH.
func (lm *LayerManager) PkgRootDir() string {
	return filepath.Join(lm.baseDir, "persistent", "pkgroot")
}

// Diff returns the files in the persistent upper layer (delta from base).
func (lm *LayerManager) Diff() ([]string, error) {
	upper := filepath.Join(lm.baseDir, "persistent", "pkg", "upper")
	var files []string

	err := filepath.Walk(upper, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(upper, path)
		if rel != "." {
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

type layerManifest struct {
	Packages []string `json:"packages"`
}

func (lm *LayerManager) manifestPath() string {
	return filepath.Join(lm.baseDir, "persistent", "manifest.json")
}

func (lm *LayerManager) loadManifest() (*layerManifest, error) {
	path := lm.manifestPath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &layerManifest{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m layerManifest
	return &m, json.Unmarshal(data, &m)
}

func (lm *LayerManager) saveManifest(m *layerManifest) error {
	path := lm.manifestPath()
	os.MkdirAll(filepath.Dir(path), 0755)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (lm *LayerManager) updateManifest(fn func(*layerManifest)) error {
	m, err := lm.loadManifest()
	if err != nil {
		return err
	}
	fn(m)
	return lm.saveManifest(m)
}

// copyDir recursively copies src into dst.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
