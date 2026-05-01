// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package tools manages bootstrap of tools required by ush runtime.
// If the host system doesn't have apt/dpkg (e.g., Vanilla OS), downloads
// binaries from official Debian mirror and extracts them to ~/.local/share/ush/tools/.
package tools

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// httpClient with reasonable timeout to avoid hanging on slow mirrors.
var httpClient = &http.Client{Timeout: 60 * time.Second}

const (
	// Debian stable mirror (bookworm) - HTTPS to prevent MITM.
	debianMirror = "https://deb.debian.org/debian"
	debianDist   = "bookworm"
	debianArch   = "amd64"
)

// Minimal packages required for apt-get + dpkg.
// Format: "name:version_partial:pool_path".
// Versions pinned for reproducibility; updatable via updateToolVersions().
var requiredPackages = []pkgSpec{
	{name: "apt", poolPath: "pool/main/a/apt"},
	{name: "dpkg", poolPath: "pool/main/d/dpkg"},
	{name: "libapt-pkg6.0", poolPath: "pool/main/a/apt"},
	{name: "libstdc++6", poolPath: "pool/main/g/gcc-12"},
	{name: "libgcc-s1", poolPath: "pool/main/g/gcc-12"},
	{name: "liblz4-1", poolPath: "pool/main/l/lz4"},
	{name: "libzstd1", poolPath: "pool/main/z/zstd"},
	{name: "liblzma5", poolPath: "pool/main/x/xz-utils"},
}

type pkgSpec struct {
	name     string
	poolPath string
}

// ToolsDir returns the path to the local tools directory.
func ToolsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/ush-tools"
	}
	return filepath.Join(home, ".local", "share", "ush", "tools")
}

// AptGetPath returns the path to apt-get executable, searching in cascade:
//  1. ~/.local/share/ush/tools/usr/bin/apt-get  (local bootstrap)
//  2. /usr/local/bin/apt-get
//  3. /usr/bin/apt-get
//
// Returns empty string if not found.
func AptGetPath() string {
	return findBin("apt-get")
}

// DpkgPath returns the path to dpkg executable (same search order).
func DpkgPath() string {
	return findBin("dpkg")
}

func findBin(name string) string {
	candidates := []string{
		filepath.Join(ToolsDir(), "usr", "bin", name),
		filepath.Join(ToolsDir(), "bin", name),
		"/usr/local/bin/" + name,
		"/usr/bin/" + name,
		"/bin/" + name,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// EnsureApt verifies that apt-get and dpkg are available.
// If not found on the system, it downloads them from the Debian mirror and extracts
// them to ToolsDir(). Also ensures apt method drivers (http, https) are present.
// Must be called from the parent process (outside the namespace).
func EnsureApt() error {
	if AptGetPath() != "" && DpkgPath() != "" {
		ushlog.Debug("tools: apt-get and dpkg found, skip bootstrap")
		// Even if apt is on the system, check that method drivers exist
		// in the tools dir (needed when running inside a namespace where
		// /usr is RO and the methods path may need explicit configuration).
		ensureMethodsSymlinks()
		return nil
	}

	fmt.Fprintln(os.Stderr, "USH: first run - downloading apt/dpkg from deb.debian.org (this happens once)...")
	toolsDir := ToolsDir()
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		return fmt.Errorf("tools: mkdir %s: %w", toolsDir, err)
	}

	// Download the package index to find the exact URLs.
	fmt.Fprintf(os.Stderr, "USH: fetching package index from Debian %s...\n", debianDist)
	pkgIndex, err := fetchPackageIndex()
	if err != nil {
		return fmt.Errorf("tools: cannot reach Debian mirror (%s), check your internet connection: %w", debianMirror, err)
	}

	var failed []string
	for _, pkg := range requiredPackages {
		// Skip if already present.
		if findBin(pkg.name) != "" {
			continue
		}
		url, err := findPackageURL(pkgIndex, pkg.name)
		if err != nil {
			ushlog.Warn("tools: package not found in index", "pkg", pkg.name, "err", err)
			failed = append(failed, pkg.name)
			continue
		}
		fmt.Fprintf(os.Stderr, "USH: downloading %s...\n", pkg.name)
		debData, err := downloadURL(debianMirror + "/" + url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "USH: download failed for %s: %v\n", pkg.name, err)
			failed = append(failed, pkg.name)
			continue
		}
		if err := extractDeb(debData, toolsDir); err != nil {
			fmt.Fprintf(os.Stderr, "USH: extraction failed for %s: %v\n", pkg.name, err)
			failed = append(failed, pkg.name)
		}
	}

	// Ensure method drivers are available in the tools dir.
	// When host apt exists, create symlinks from the host methods to the tools dir.
	ensureMethodsSymlinks()

	if AptGetPath() == "" || DpkgPath() == "" {
		missing := []string{}
		if AptGetPath() == "" {
			missing = append(missing, "apt-get")
		}
		if DpkgPath() == "" {
			missing = append(missing, "dpkg")
		}
		if len(failed) > 0 {
			return fmt.Errorf("tools: bootstrap failed (could not download: %s), check internet connection", strings.Join(failed, ", "))
		}
		return fmt.Errorf("tools: bootstrap completed but binaries not found: %s (looked in %s)", strings.Join(missing, ", "), toolsDir)
	}
	fmt.Fprintf(os.Stderr, "USH: apt/dpkg ready\n")
	return nil
}

// ensureMethodsSymlinks creates symlinks in the tools dir for apt method drivers
// (http, https, etc.) if they exist on the host system but not in the tools dir.
// This ensures network-based package operations work inside the namespace.
func ensureMethodsSymlinks() {
	toolsDir := ToolsDir()
	methodsDir := filepath.Join(toolsDir, "usr", "lib", "apt", "methods")

	// If the tools dir already has method drivers, nothing to do.
	if _, err := os.Stat(filepath.Join(methodsDir, "http")); err == nil {
		return
	}

	// Create symlinks from host methods to tools dir.
	hostMethodsDir := "/usr/lib/apt/methods"
	hostEntries, err := os.ReadDir(hostMethodsDir)
	if err != nil {
		// Host doesn't have apt methods (unlikely if apt is installed).
		ushlog.Debug("tools: host apt methods dir not found", "dir", hostMethodsDir)
		return
	}

	os.MkdirAll(methodsDir, 0755)
	for _, entry := range hostEntries {
		src := filepath.Join(hostMethodsDir, entry.Name())
		dst := filepath.Join(methodsDir, entry.Name())
		if _, err := os.Stat(dst); err != nil {
			os.Symlink(src, dst) //nolint:errcheck
		}
	}
}

// fetchPackageIndex downloads and returns the Packages index from mirror.
func fetchPackageIndex() (string, error) {
	url := fmt.Sprintf("%s/dists/%s/main/binary-%s/Packages.gz",
		debianMirror, debianDist, debianArch)
	data, err := downloadURL(url)
	if err != nil {
		return "", err
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("gunzip packages: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read packages: %w", err)
	}
	return string(out), nil
}
