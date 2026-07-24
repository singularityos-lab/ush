// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package tools manages bootstrap of tools required by ush runtime.
// If the host system doesn't have apt/dpkg, downloads
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
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/ulikunitz/xz"
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
	{name: "libbz2-1.0", poolPath: "pool/main/b/bzip2"},
	{name: "libxxhash0", poolPath: "pool/main/x/xxhash"},
	// Sinty ships a partial libsystemd shim without sd_bus_* symbols; stage the
	// real Debian libsystemd0 so libapt-pkg (which needs sd_bus_open_system)
	// resolves against it via the guest-leading LD_LIBRARY_PATH.
	{name: "libsystemd0", poolPath: "pool/main/s/systemd"},
	{name: "libmd0", poolPath: "pool/main/libm/libmd"},
	{name: "libselinux1", poolPath: "pool/main/libs/libselinux"},
	// GNU tar: dpkg-deb invokes `tar --warning=no-timestamp` which the guest's
	// BusyBox tar rejects; ship the real one and stage it ahead of BusyBox in PATH.
	{name: "tar", poolPath: "pool/main/t/tar"},
	{name: "libacl1", poolPath: "pool/main/a/acl"},
	// Signature verification: gpgv binary + the Debian archive keyring, so apt
	// authenticates InRelease instead of installing unverified indices.
	{name: "gpgv", poolPath: "pool/main/g/gpgv"},
	{name: "debian-archive-keyring", poolPath: "pool/main/d/debian-archive-keyring"},
	// bash is Essential in Debian, so apt assumes it is already present and never
	// pulls it in as a dependency -- but the Sinty base is BusyBox-only, so every
	// installed package with a `#!/bin/bash` script fails to exec (ENOENT on the
	// interpreter). Stage it here so the guest has a real bash; the fs setup then
	// exposes it at the absolute /bin/bash the shebangs need. libtinfo6 is bash's
	// non-libc shared dep and is staged into the guest lib path like the apt libs.
	{name: "bash", poolPath: "pool/main/b/bash"},
	{name: "libtinfo6", poolPath: "pool/main/n/ncurses"},
	// perl-base runs Debian debconf maintainer scripts. debconf's confmodule execs
	// /usr/share/debconf/frontend (perl); the busybox base has no perl, so every
	// package with a debconf postinst dies with exit 127. perl-base is Priority
	// required. setupPerl exposes it at /usr/bin/perl in the guest.
	{name: "perl-base", poolPath: "pool/main/p/perl"},
	// debconf is INFRASTRUCTURE, not a package to install at runtime: maintainer
	// scripts source /usr/share/debconf/confmodule and exec the perl frontend, which
	// loads Debconf::* modules from /usr/share/perl5/Debconf. When debconf is only
	// installed at runtime, those modules land BEHIND the rootless /usr overlay and
	// are invisible in-session (the overlay never surfaces a deep dir written behind
	// the mount), so `use Debconf::Db` dies "Can't locate" and every debconf postinst
	// fails. Staging debconf into the tools tree (like perl-base) makes seedDebconfBase
	// pre-populate the guest /usr with confmodule + frontend + Debconf modules BEFORE
	// the overlay mounts, so they are present and visible. Pure-perl, only dep is
	// perl-base. Used with DEBIAN_FRONTEND=noninteractive.
	{name: "debconf", poolPath: "pool/main/d/debconf"},
	// perl links libcrypt.so.1, which the Sinty base does not ship (libc/libm it
	// does). Stage it like libtinfo6 for bash; it lands in the guest lib path so
	// the /usr/bin/perl seeded from perl-base resolves it.
	{name: "libcrypt1", poolPath: "pool/main/libx/libxcrypt"},
	// libc-bin ships getent, which countless maintainer scripts call to test
	// whether a user/group already exists (getent passwd/group) before creating
	// it. The busybox base has no getent, so those scripts die "getent: not
	// found". Staging it into the tools tree lets seedShadowTools expose
	// /usr/bin/getent in the guest. libnss_files (in the base libc) backs it.
	{name: "libc-bin", poolPath: "pool/main/g/glibc"},
}

type pkgSpec struct {
	name     string
	poolPath string
}

// SystemToolsDir is the read-only tools tree an image can ship pre-baked, so the
// first run costs nothing. Deliberately not overridable from the environment:
// it is where apt and dpkg are executed from, and letting a caller redirect it
// would let any user point the sandbox at a trojaned apt.
const SystemToolsDir = "/usr/share/ush/tools"

// ToolsDir returns the tools directory in use: the pre-baked system tree when
// the image ships one, otherwise the per-user one that EnsureApt downloads into.
// The system tree can stay read-only, since EnsureApt writes nothing once apt,
// dpkg and the method drivers are all present.
func ToolsDir() string {
	if _, err := os.Stat(filepath.Join(SystemToolsDir, "usr", "bin", "apt-get")); err == nil {
		return SystemToolsDir
	}
	return UserToolsDir()
}

// UserToolsDir is the writable per-user tools tree, used when the image ships no
// pre-baked one (and as the bootstrap target).
func UserToolsDir() string {
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
	// Both trees: the pre-baked system one (ToolsDir when present) and the
	// per-user one EnsureApt downloads into, so a half-baked image that still
	// needed a download is found either way.
	candidates := []string{
		filepath.Join(SystemToolsDir, "usr", "bin", name),
		filepath.Join(SystemToolsDir, "bin", name),
		filepath.Join(UserToolsDir(), "usr", "bin", name),
		filepath.Join(UserToolsDir(), "bin", name),
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
	// Download into the per-user tree, never ToolsDir(): if a pre-baked system
	// tree exists it is read-only, and in that case AptGetPath already returned
	// above so we would not be here anyway. Being explicit keeps it that way.
	return bootstrapInto(UserToolsDir())
}

// BakeToolsInto populates a tools tree at an arbitrary path so an image build can
// pre-stage it at SystemToolsDir. Same code and same package set as the runtime
// bootstrap, so what ships is exactly what the download would have produced.
// Build-time only: needs network and writes to dir.
func BakeToolsInto(dir string) error {
	fmt.Fprintf(os.Stderr, "USH: baking apt/dpkg tools into %s\n", dir)
	return bootstrapInto(dir)
}

// bootstrapInto downloads and extracts the required Debian packages into toolsDir,
// then ensures the apt method drivers are present.
func bootstrapInto(toolsDir string) error {
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
		// Skip only if already extracted into the tools dir. Do NOT skip on a
		// same-named system binary: the guest's BusyBox tar is not a substitute
		// for GNU tar, and matching it here silently left tar un-bootstrapped.
		if _, err := os.Stat(filepath.Join(toolsDir, "usr", "bin", pkg.name)); err == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(toolsDir, "bin", pkg.name)); err == nil {
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

	// Ensure method drivers are available in the tools dir. The extracted apt
	// package normally ships them, so this is usually a no-op; the symlink path
	// only kicks in on a host that lacks them in the .deb.
	ensureMethodsSymlinksIn(toolsDir)

	// Verify against toolsDir directly, not the global search path: at build time
	// SystemToolsDir does not yet exist, so AptGetPath would look in the wrong place.
	haveApt := statBin(toolsDir, "apt-get")
	haveDpkg := statBin(toolsDir, "dpkg")
	if !haveApt || !haveDpkg {
		missing := []string{}
		if !haveApt {
			missing = append(missing, "apt-get")
		}
		if !haveDpkg {
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

// statBin reports whether name exists under toolsDir/usr/bin or toolsDir/bin.
func statBin(toolsDir, name string) bool {
	for _, sub := range []string{"usr/bin", "bin"} {
		if _, err := os.Stat(filepath.Join(toolsDir, sub, name)); err == nil {
			return true
		}
	}
	return false
}

// ensureMethodsSymlinks creates symlinks in the tools dir for apt method drivers
// (http, https, etc.) if they exist on the host system but not in the tools dir.
// This ensures network-based package operations work inside the namespace.
func ensureMethodsSymlinks() { ensureMethodsSymlinksIn(ToolsDir()) }

func ensureMethodsSymlinksIn(toolsDir string) {
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

// findPackageURL searches the Packages index for the Filename field of a package.
func findPackageURL(index, pkgName string) (string, error) {
	var inPkg bool
	var filename string
	for _, line := range strings.Split(index, "\n") {
		if strings.HasPrefix(line, "Package: ") {
			name := strings.TrimPrefix(line, "Package: ")
			inPkg = (name == pkgName)
			filename = ""
		}
		if inPkg && strings.HasPrefix(line, "Filename: ") {
			filename = strings.TrimPrefix(line, "Filename: ")
		}
		if inPkg && filename != "" && line == "" {
			return filename, nil
		}
	}
	if filename != "" {
		return filename, nil
	}
	return "", fmt.Errorf("package %q not found", pkgName)
}

func downloadURL(url string) ([]byte, error) {
	resp, err := httpClient.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("http get %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// extractDeb extracts the contents of a .deb archive into destDir.
// .deb format is an ar archive containing data.tar.{gz,xz,zst,bz2}.
func extractDeb(debData []byte, destDir string) error {
	// Verify ar magic.
	if len(debData) < 8 || string(debData[:8]) != "!<arch>\n" {
		return fmt.Errorf("not a valid ar archive")
	}

	r := bytes.NewReader(debData[8:])
	for {
		// Read ar header (60 bytes).
		var hdr [60]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return fmt.Errorf("read ar header: %w", err)
		}

		// Magic check.
		if string(hdr[58:60]) != "`\n" {
			return fmt.Errorf("invalid ar magic")
		}

		name := strings.TrimRight(string(hdr[0:16]), " /")
		sizeStr := strings.TrimSpace(string(hdr[48:58]))
		var size int64
		fmt.Sscanf(sizeStr, "%d", &size)

		// Read ar content.
		content := make([]byte, size)
		if _, err := io.ReadFull(r, content); err != nil {
			return fmt.Errorf("read ar content %s: %w", name, err)
		}
		// Align to 2 bytes.
		if size%2 != 0 {
			var pad [1]byte
			r.Read(pad[:]) //nolint:errcheck
		}

		// Search for data.tar.* and extract it.
		if strings.HasPrefix(name, "data.tar") {
			if err := extractTar(name, content, destDir); err != nil {
				return fmt.Errorf("extract tar %s: %w", name, err)
			}
			return nil
		}
	}
	return fmt.Errorf("data.tar not found in .deb")
}

// extractTar extracts a tar archive (with various compressions) into destDir.
func extractTar(name string, data []byte, destDir string) error {
	var r io.Reader = bytes.NewReader(data)

	switch {
	case strings.HasSuffix(name, ".gz"):
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	case strings.HasSuffix(name, ".bz2"):
		r = bzip2.NewReader(r)
	case strings.HasSuffix(name, ".xz"):
		// Decompress in-process: the target may be a minimal image (busybox tar has
		// no --xz, no `xz` binary), and modern Debian packages ship data.tar.xz.
		xr, err := xz.NewReader(r)
		if err != nil {
			return fmt.Errorf("xz reader: %w", err)
		}
		r = xr
	case strings.HasSuffix(name, ".zst"):
		zr, err := zstd.NewReader(r)
		if err != nil {
			return fmt.Errorf("zstd reader: %w", err)
		}
		defer zr.Close()
		r = zr
	}

	return extractTarReader(r, destDir)
}

func extractTarReader(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, hdr.Name)
		// Security: prevent path traversal.
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, os.FileMode(hdr.Mode))
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				continue
			}
			io.Copy(f, tr) //nolint:errcheck
			f.Close()
		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(target), 0755)
			os.Remove(target)
			os.Symlink(hdr.Linkname, target) //nolint:errcheck
		case tar.TypeLink:
			os.MkdirAll(filepath.Dir(target), 0755)
			os.Link(filepath.Join(destDir, hdr.Linkname), target) //nolint:errcheck
		}
	}
	return nil
}

// keep the encoding/binary import referenced
var _ = binary.LittleEndian
