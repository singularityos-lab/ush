// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package fs manages the guest filesystem: overlay, bind mount, pivot_root.
//
// Guest rootfs layout:
//
//	/proc          -> new proc in the pid namespace
//	/run           -> per-session tmpfs
//	/tmp           -> tmpfs
//	/sys           -> bind RO from host (minimized)
//	/dev           -> bind from host (selective)
//	/usr           -> bind RO from host
//	/lib           -> bind RO from host (or symlink on Debian)
//	/lib64         -> bind RO from host (if it exists)
//	/bin           -> bind RO from host (or symlink)
//	/sbin          -> bind RO from host (or symlink)
//	/etc           -> overlayfs (lower=host /etc, upper=layer/etc)
//	/var           -> overlayfs (lower=host /var, upper=layer/var)
//	/home/$USER    -> bind RW from host
//	/run/user/$UID -> bind from host (Wayland, PipeWire, D-Bus)
//	/dev/dri       -> bind from host (GPU)
package fs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/preload"
	"golang.org/x/sys/unix"
)

// GuestFS describes the guest filesystem and manages its lifecycle.
type GuestFS struct {
	// GuestRoot is the temporary directory used as the guest rootfs.
	GuestRoot string

	// LayerDir is the layer directory (~/.local/share/ush/layers).
	LayerDir string

	// SessionID identifies the current session (for ephemeral layers).
	SessionID string

	// HostUID/HostGID of the user who launched ush.
	HostUID int
	HostGID int

	// XDGRuntimeDir is the host's XDG_RUNTIME_DIR.
	XDGRuntimeDir string

	// HomeDir is the host user's home directory.
	HomeDir string

	// ToolsDir is the path of tools downloaded by EnsureApt
	// (~/.local/share/ush/tools). Empty if using the system ones.
	ToolsDir string

	// ExtraBinds are explicit host paths to expose into the guest, as
	// "host_path:guest_path[:ro]". This is the allow-list knob for letting the
	// guest reach specific host resources (e.g. a user-installed binary RO, or
	// an app's credentials) without opening the whole home. Source of the
	// per-app sandbox model.
	ExtraBinds []string

	// TrustedDevDirs are user-confirmed developer directories (granted via
	// `perm trust-dir`). They are bound read-write straight from the host with no
	// VCS-metadata isolation and are exempt from exec stripping: the user wants to
	// build, run and commit there normally. Stored on the host outside the guest's
	// view, so a compromised guest cannot self-grant.
	TrustedDevDirs []string

	// DevProfile selects the developer (dsh) world: a SEPARATE persistent home
	// (so the dev environment never shares state with the secure ush home) and
	// /dev/fuse exposed (fuse-overlayfs for nested rootless containers).
	DevProfile bool
}

// persistentHomeName is the per-profile guest home directory under the layer
// dir. ush and dsh get distinct homes so the two worlds never share state.
func (g *GuestFS) persistentHomeName() string {
	if g.DevProfile {
		return "dev-home"
	}
	return "home"
}

// Setup builds the guest filesystem.
// Must be called from the child process (inside the namespace).
func (g *GuestFS) Setup() error {
	ushlog.Info("fs: setup guest rootfs", "root", g.GuestRoot)

	if err := g.createDirs(); err != nil {
		return err
	}
	if err := g.makeSelfPrivate(); err != nil {
		return err
	}
	if err := g.mountTmpRoots(); err != nil {
		return err
	}
	if err := g.bindRunSystemd(); err != nil {
		ushlog.Debug("fs: host /run/systemd not available", "err", err)
	}
	if err := g.bindRODirs(); err != nil {
		return err
	}
	if err := g.setupUsr(); err != nil {
		return err
	}
	if err := g.setupEtc(); err != nil {
		return err
	}
	if err := g.setupVar(); err != nil {
		return err
	}
	if err := g.bindHome(); err != nil {
		return err
	}
	if err := g.bindPkgLayer(); err != nil {
		return err
	}
	if err := g.applyExtraBinds(); err != nil {
		return err
	}
	if err := g.bindTrustedDevDirs(); err != nil {
		return err
	}
	if err := g.bindDevices(); err != nil {
		return err
	}
	if err := g.bindXDGRuntime(); err != nil {
		return err
	}
	if err := g.blockPackageManagers(); err != nil {
		return err
	}
	if err := g.pivotRoot(); err != nil {
		return err
	}

	ushlog.Info("fs: rootfs ready")
	return nil
}

// createDirs creates the necessary directories in the guest root.
func (g *GuestFS) createDirs() error {
	dirs := []string{
		g.GuestRoot,
		filepath.Join(g.GuestRoot, "proc"),
		filepath.Join(g.GuestRoot, "run"),
		filepath.Join(g.GuestRoot, "tmp"),
		filepath.Join(g.GuestRoot, "sys"),
		filepath.Join(g.GuestRoot, "dev"),
		filepath.Join(g.GuestRoot, "dev", "dri"),
		filepath.Join(g.GuestRoot, "dev", "pts"),
		filepath.Join(g.GuestRoot, "usr"),
		filepath.Join(g.GuestRoot, "lib"),
		filepath.Join(g.GuestRoot, "lib64"),
		filepath.Join(g.GuestRoot, "bin"),
		filepath.Join(g.GuestRoot, "sbin"),
		filepath.Join(g.GuestRoot, "etc"),
		filepath.Join(g.GuestRoot, "var"),
		filepath.Join(g.GuestRoot, "root"),
		filepath.Join(g.GuestRoot, "old_root"),
	}

	// the user home
	if g.HomeDir != "" {
		dirs = append(dirs, filepath.Join(g.GuestRoot, g.HomeDir))
	}

	// and XDG_RUNTIME_DIR
	if g.XDGRuntimeDir != "" {
		dirs = append(dirs, filepath.Join(g.GuestRoot, g.XDGRuntimeDir))
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("fs: mkdir %s: %w", d, err)
		}
	}
	return nil
}

// makeSelfPrivate makes the mount namespace private (MS_PRIVATE|MS_REC)
// so that our mounts don't propagate to the host.
func (g *GuestFS) makeSelfPrivate() error {
	return unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, "")
}

// mountTmpRoots mounts /proc, /run, /tmp as tmpfs/proc in the guest.
func (g *GuestFS) mountTmpRoots() error {
	mounts := []struct {
		src, dst, fstype, data string
		flags                  uintptr
	}{
		{"proc", filepath.Join(g.GuestRoot, "proc"), "proc", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"tmpfs", filepath.Join(g.GuestRoot, "run"), "tmpfs", "mode=755", unix.MS_NOSUID | unix.MS_NODEV},
		{"tmpfs", filepath.Join(g.GuestRoot, "tmp"), "tmpfs", "mode=1777", unix.MS_NOSUID | unix.MS_NODEV},
	}

	for _, m := range mounts {
		ushlog.Debug("fs: mount", "type", m.fstype, "dst", m.dst)
		if err := unix.Mount(m.src, m.dst, m.fstype, m.flags, m.data); err != nil {
			return fmt.Errorf("fs: mount %s on %s: %w", m.fstype, m.dst, err)
		}
	}
	return nil
}

// bindRunSystemd bind-mounts the host's /run/systemd read-only into the guest.
// This lets sd_booted() return true inside the guest (it checks for
// /run/systemd/private), which is required for systemd --user to start.
// Non-fatal: if the host doesn't have /run/systemd, systemd --user simply
// won't be available.
func (g *GuestFS) bindRunSystemd() error {
	src := "/run/systemd"
	dst := filepath.Join(g.GuestRoot, "run", "systemd")

	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("host /run/systemd not found")
	}

	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("fs: mkdir %s: %w", dst, err)
	}

	flags := uintptr(unix.MS_BIND | unix.MS_REC | unix.MS_RDONLY)
	if err := unix.Mount(src, dst, "", flags, ""); err != nil {
		return fmt.Errorf("fs: bind /run/systemd: %w", err)
	}
	// Remount read-only (MS_BIND alone ignores MS_RDONLY on first mount).
	roFlags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY)
	if err := unix.Mount("", dst, "", roFlags, ""); err != nil {
		ushlog.Debug("fs: /run/systemd remount ro failed (non-fatal)", "err", err)
	}
	ushlog.Debug("fs: /run/systemd bound from host")
	return nil
}

// /sys is mounted as fresh sysfs (avoids MS_REMOUNT issues in user namespace).
func (g *GuestFS) bindRODirs() error {
	dirs := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}

	for _, d := range dirs {
		dst := filepath.Join(g.GuestRoot, d)

		// nothing to do if the host dir is not there
		if _, err := os.Lstat(d); os.IsNotExist(err) {
			continue
		}

		// If it's a symlink on the host, recreate it in the guest.
		fi, err := os.Lstat(d)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(d)
			if err != nil {
				continue
			}
			os.Remove(dst)
			if err := os.Symlink(target, dst); err != nil && !os.IsExist(err) {
				ushlog.Warn("fs: symlink failed", "path", d, "err", err)
			}
			continue
		}

		if err := bindMount(d, dst, true); err != nil {
			return fmt.Errorf("fs: bind ro %s: %w", d, err)
		}
	}

	sysDst := filepath.Join(g.GuestRoot, "sys")

	// dsh: bind the host /sys NON-recursively, so the host's cgroup mount is NOT
	// pulled in (that real-root cgroup is what made a fresh mount EBUSY). Then put
	// a FRESH cgroup2 on the now-empty /sys/fs/cgroup: with the guest cgroup
	// namespace it is rooted at the delegated systemd scope, writable, which is
	// what nested rootless podman needs.
	if g.DevProfile {
		if err := unix.Mount("/sys", sysDst, "", unix.MS_BIND, ""); err != nil {
			ushlog.Warn("fs: dev /sys bind failed", "err", err)
		}
		cgDst := filepath.Join(sysDst, "fs", "cgroup")
		_ = os.MkdirAll(cgDst, 0755)
		if err := unix.Mount("cgroup2", cgDst, "cgroup2",
			unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			ushlog.Warn("fs: cgroup2 mount failed", "err", err)
		}
		return nil
	}

	// Secure profile: fresh read-only sysfs (not a bind, to avoid MS_REMOUNT
	// issues in the user namespace).
	sysFlags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY)
	if err := unix.Mount("sysfs", sysDst, "sysfs", sysFlags, ""); err != nil {
		// Fallback: bind from host without remount RO (best-effort).
		ushlog.Warn("fs: sysfs mount failed, fallback bind", "err", err)
		if err2 := unix.Mount("/sys", sysDst, "", unix.MS_BIND|unix.MS_REC, ""); err2 != nil {
			ushlog.Warn("fs: /sys bind failed, skipping", "err", err2)
		}
	}

	return nil
}

// setupUsr is a no-op: /usr is bind-mounted RO by bindRODirs().
// Packages are installed into pkgPrefix (via dpkg --instdir) instead
// of /usr, so /usr can stay read-only.
func (g *GuestFS) setupUsr() error {
	return nil
}

// setupEtc populates the guest /etc from the host by copying into a tmpfs so
// maintainer scripts can write to it. It does not use overlayfs because /etc may
// already be overlayfs (which cannot be stacked in a user namespace) as on
// ABRoot/Vanilla OS systems.
func (g *GuestFS) setupEtc() error {
	etcDst := filepath.Join(g.GuestRoot, "etc")

	// tmpfs over /etc
	if err := unix.Mount("tmpfs", etcDst, "tmpfs",
		unix.MS_NOSUID|unix.MS_NODEV, "mode=755"); err != nil {
		return fmt.Errorf("fs: mount tmpfs /etc: %w", err)
	}

	// Essential files/directories to copy to the tmpfs.
	// All directories are copied so maintainer scripts can write to /etc.
	essentialFiles := []string{
		"passwd", "shadow", "group", "gshadow", "subuid", "subgid",
		"hosts", "hostname", "resolv.conf", "nsswitch.conf",
		"os-release", "lsb-release", "debian_version",
		"timezone", "locale.gen", "locale.conf", "environment",
		"ld.so.conf", "ld.so.cache",
		"machine-id",
		"fstab", "mtab",
		"login.defs", "shells",
		"debconf.conf",
	}
	essentialDirs := []string{
		"apt", "dpkg", "pam.d", "security",
		"systemd", "dbus-1", "xdg",
		"profile.d", "default",
		"ld.so.conf.d",
		"ssl", "ca-certificates", "alternatives",
		"fonts", "X11",
	}
	// Bind RO for large directories (currently none, all /etc dirs are
	// copied to tmpfs so maintainer scripts can write to them).
	bindRODirs := []string{}

	// Copy individual files.
	for _, f := range essentialFiles {
		src := filepath.Join("/etc", f)
		dst := filepath.Join(etcDst, f)
		copyFileIfExists(src, dst)
	}

	// Fix resolv.conf: replace loopback-only nameservers with public fallbacks
	// so DNS works inside the isolated network namespace (e.g. systemd-resolved
	// stub at 127.0.0.53 is unreachable inside the guest net namespace).
	fixResolvConf(filepath.Join(etcDst, "resolv.conf"))

	// Copy directories (recursive, best-effort).
	for _, d := range essentialDirs {
		src := filepath.Join("/etc", d)
		dst := filepath.Join(etcDst, d)
		if fi, err := os.Stat(src); err == nil && fi.IsDir() {
			os.MkdirAll(dst, fi.Mode())
			copyDirContents(src, dst) //nolint:errcheck
		}
	}

	// Bind RO for large directories.
	for _, d := range bindRODirs {
		src := filepath.Join("/etc", d)
		dst := filepath.Join(etcDst, d)
		if fi, err := os.Stat(src); err == nil && fi.IsDir() {
			os.MkdirAll(dst, fi.Mode())
			if err := bindMount(src, dst, true); err != nil {
				ushlog.Warn("fs: bind /etc/"+d+" failed, skip", "err", err)
			}
		}
	}

	// Removes apt.conf.d files that register hooks pointing to scripts not
	// present in the guest (distrobox, snap, etc.).
	purgeContainerAptHooks(filepath.Join(etcDst, "apt", "apt.conf.d"), g.GuestRoot)

	// Ensure a minimal debconf.conf exists so that Debian package preinst/postinst
	// scripts that invoke debconf don't fail with "No config file found".
	// On non-Debian hosts (Vanilla OS, Fedora…) this file doesn't exist.
	ensureDebconfConf(etcDst)

	// Ensure a valid Debian sources.list in the guest.
	// On Vanilla OS / non-Debian systems there is no sources.list.
	// If created from scratch, invalidate the apt lists (they might be from another distro).
	if ensureDebianSources(filepath.Join(etcDst, "apt")) {
		if err := invalidateAptLists(g.GuestRoot); err != nil {
			ushlog.Warn("fs: unable to clear apt lists", "err", err)
		}
	}

	ushlog.Debug("fs: /etc configured via tmpfs+copy")
	return nil
}

// ensureDebianSources ensures that /etc/apt/sources.list in the guest contains
// at least one valid Debian entry. On non-Debian systems (Vanilla OS, Fedora…)
// there is no sources.list, so apt finds no packages.
// Returns true if it created/replaced the sources.list (lists must be re-downloaded).
func ensureDebianSources(aptDir string) bool {
	os.MkdirAll(aptDir, 0755) //nolint:errcheck
	sourcesList := filepath.Join(aptDir, "sources.list")

	// Check if a sources.list with valid deb entries already exists.
	if data, err := os.ReadFile(sourcesList); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "deb ") {
				return false // sources.list valid, nothing to do
			}
		}
	}

	// Create sources.list pointing to Debian stable.
	// [trusted=yes] bypasses GPG verification: the guest doesn't have the Debian keyring
	// and apt-key might not be available in the namespace.
	content := "deb [trusted=yes] http://deb.debian.org/debian/ stable main contrib non-free non-free-firmware\n" +
		"deb [trusted=yes] http://security.debian.org/debian-security stable-security main contrib non-free non-free-firmware\n"
	if err := os.WriteFile(sourcesList, []byte(content), 0644); err != nil {
		ushlog.Warn("fs: unable to create Debian sources.list", "err", err)
		return false
	}
	ushlog.Info("fs: Debian sources.list created (non-Debian system detected)")

	// Remove sources.list.d to avoid host repos (e.g. VanillaOS, Ubuntu PPA).
	sourcesD := filepath.Join(aptDir, "sources.list.d")
	if entries, err := os.ReadDir(sourcesD); err == nil {
		for _, e := range entries {
			os.Remove(filepath.Join(sourcesD, e.Name())) //nolint:errcheck
		}
		ushlog.Info("fs: sources.list.d purged (host repos removed)")
	}

	return true
}

// invalidateAptLists empties /var/lib/apt/lists (or a subdirectory)
// so that apt update re-downloads the correct lists for the guest's sources.list.
// The base parameter can be guestRoot (appends var/lib/apt/lists)
// or directly the apt/lists directory.
func invalidateAptLists(base string) error {
	// Try first as a direct path (varDst passed from setupVar).
	listsDir := filepath.Join(base, "lib", "apt", "lists")
	if _, err := os.Stat(listsDir); os.IsNotExist(err) {
		// Try as guestRoot.
		listsDir = filepath.Join(base, "var", "lib", "apt", "lists")
	}
	entries, err := os.ReadDir(listsDir)
	if err != nil {
		return nil // dir doesn't exist, no problem
	}
	for _, e := range entries {
		if !e.IsDir() {
			os.Remove(filepath.Join(listsDir, e.Name())) //nolint:errcheck
		}
	}
	ushlog.Info("fs: apt lists cleared")
	return nil
}

// purgeContainerAptHooks scans the directory and removes any apt configuration
// file that contains a hook (DPkg::Pre/Post-Invoke, etc.) pointing to
// a script not present in the guest rootfs.
func purgeContainerAptHooks(dir, guestRoot string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	hookRe := regexp.MustCompile(`(?i)(DPkg|APT)::[A-Za-z:-]+\s*\{([^}]+)\}`)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		matches := hookRe.FindAllStringSubmatch(string(data), -1)
		for _, m := range matches {
			script := strings.TrimSpace(m[2])
			// Check if the script exists in the guest (not on the host).
			guestScript := filepath.Join(guestRoot, script)
			if _, err := os.Stat(guestScript); os.IsNotExist(err) {
				ushlog.Debug("fs: removing container-specific apt hook", "file", e.Name(), "script", script)
				os.Remove(path) //nolint:errcheck
				break
			}
		}
	}
}

// ensureDebconfConf creates a minimal /etc/debconf.conf if it doesn't already
// exist. Debian package preinst/postinst scripts invoke debconf which reads this
// file; without it debconf dies with "No config file found" on non-Debian hosts.
func ensureDebconfConf(etcDst string) {
	dst := filepath.Join(etcDst, "debconf.conf")
	if _, err := os.Stat(dst); err == nil {
		return // already present (copied from host)
	}
	const debconfConf = `# Debconf configuration for USH guest environment
# Minimal noninteractive config - generated by USH
Name: config
Driver: File
Mode: 644
Reject-Type: password
Filename: /var/cache/debconf/config.dat

Name: passwords
Driver: File
Mode: 600
Filename: /var/cache/debconf/passwords.dat

Name: template
Driver: File
Filename: /var/cache/debconf/templates.dat
`
	os.WriteFile(dst, []byte(debconfConf), 0644) //nolint:errcheck
	// Create the debconf cache directory referenced in the config.
	os.MkdirAll(filepath.Join(etcDst, "..", "var", "cache", "debconf"), 0755) //nolint:errcheck
}

// fixResolvConf rewrites /etc/resolv.conf for the guest network namespace. It
// always materialises a plain file (never a symlink) and always uses public
// nameservers, because:
//   - On systemd hosts, /etc/resolv.conf is a symlink into /run/systemd/resolve/
//     which becomes dangling after pivot_root (guest /run is a fresh tmpfs).
//   - The guest network namespace is isolated; the host's DNS resolver
//     (whether 127.0.0.53 or a local router IP like 10.20.10.1) is unreachable
//     or wrong inside the guest namespace.
//   - pasta NATs all traffic, so direct public DNS (1.1.1.1/8.8.8.8) works.
func fixResolvConf(path string) {
	const content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	// Remove symlink or existing file unconditionally.
	os.Remove(path)                           //nolint:errcheck
	os.WriteFile(path, []byte(content), 0644) //nolint:errcheck
	ushlog.Debug("fs: resolv.conf written with public DNS")
}

// copyFileIfExists copies src to dst if src exists; ignores errors.
func copyFileIfExists(src, dst string) {
	fi, err := os.Lstat(src)
	if err != nil {
		return
	}
	// Recreate symlink.
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return
		}
		os.MkdirAll(filepath.Dir(dst), 0755)
		os.Remove(dst)
		os.Symlink(target, dst) //nolint:errcheck
		return
	}
	// Skip special files.
	if fi.Mode()&os.ModeType != 0 {
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(dst), 0755)
	os.WriteFile(dst, data, fi.Mode()) //nolint:errcheck
}

// copyDirContents recursively copies src -> dst (best-effort).
func copyDirContents(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == "." {
			return nil
		}
		dstPath := filepath.Join(dst, rel)

		if d.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil
			}
			os.MkdirAll(filepath.Dir(dstPath), 0755)
			os.Symlink(target, dstPath) //nolint:errcheck
			return nil
		}
		if d.IsDir() {
			info, _ := d.Info()
			mode := os.FileMode(0755)
			if info != nil {
				mode = info.Mode()
			}
			os.MkdirAll(dstPath, mode)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode()&os.ModeType != 0 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		os.MkdirAll(filepath.Dir(dstPath), 0755)
		os.WriteFile(dstPath, data, info.Mode()) //nolint:errcheck
		return nil
	})
}

// setupOverlay configures an overlayfs for a directory (e.g. "var").
// Tries userxattr first (required in user namespace since kernel 5.11),
// then falls back to regular overlay. If overlayfs is entirely unavailable
// (unsupported kernel, missing module, etc.) returns an error so the caller
// can use the tmpfs fallback.
func (g *GuestFS) setupOverlay(dir string) error {
	upper := filepath.Join(g.LayerDir, "persistent", dir, "upper")
	work := filepath.Join(g.LayerDir, "persistent", dir, "work")
	lower := "/" + dir
	dst := filepath.Join(g.GuestRoot, dir)

	for _, d := range []string{upper, work} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("fs: overlay mkdir %s: %w", d, err)
		}
	}

	ushlog.Debug("fs: trying overlay mount", "dir", dir)

	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,userxattr", lower, upper, work)
	if err := unix.Mount("overlay", dst, "overlay", 0, opts); err == nil {
		ushlog.Info("fs: overlay mounted with userxattr", "dir", dir)
		return nil
	}

	opts = fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	if err := unix.Mount("overlay", dst, "overlay", 0, opts); err == nil {
		ushlog.Info("fs: overlay mounted without userxattr", "dir", dir)
		return nil
	}

	return fmt.Errorf("fs: kernel overlayfs unavailable for /%s (will use tmpfs fallback)", dir)
}

// setupVar configures /var in the guest as tmpfs with the dpkg database copied
// from the host source and persistent overlay for pkg install writes.
func (g *GuestFS) setupVar() error {
	varDst := filepath.Join(g.GuestRoot, "var")

	// First try direct overlay on /var (works if /var is on tmpfs).
	if err := g.setupOverlay("var"); err == nil {
		return nil
	}

	// Fallback: tmpfs for /var + copy dpkg/apt database for free writing.
	ushlog.Info("fs: /var overlay failed, using tmpfs+bind")
	if err := unix.Mount("tmpfs", varDst, "tmpfs",
		unix.MS_NOSUID|unix.MS_NODEV, "mode=755"); err != nil {
		return fmt.Errorf("fs: mount tmpfs /var: %w", err)
	}

	// Create minimal /var structure in tmpfs.
	varDirs := []string{
		"lib", "lib/dpkg", "lib/apt", "lib/apt/lists",
		"cache", "cache/apt", "cache/apt/archives", "cache/apt/archives/partial",
		"log", "tmp", "run", "mail", "spool", "local", "opt",
	}
	for _, d := range varDirs {
		if err := os.MkdirAll(filepath.Join(varDst, d), 0755); err != nil {
			ushlog.Warn("fs: mkdir /var/"+d, "err", err)
		}
	}

	// Copy the dpkg database into tmpfs (needed for apt-get). Not a bind RO:
	// dpkg must write lock files, and the tmpfs copy never touches the host.
	for _, dir := range []string{"/var/lib/dpkg", "/var/lib/apt/lists"} {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			rel := strings.TrimPrefix(dir, "/var/")
			dst := filepath.Join(varDst, rel)
			os.MkdirAll(dst, 0755)
			if err := copyDirContents(dir, dst); err != nil {
				ushlog.Warn("fs: partial copy of "+dir, "err", err)
			}
		}
	}

	// Clear container trigger activation files (e.g. ldconfig,
	// libc-upgrade, update-ca-certificates): they are specific to the
	// host container state and must not be processed in the guest session.
	// Keep only File (path->trigger registry) and Unincorp (already empty).
	triggersDir := filepath.Join(varDst, "lib", "dpkg", "triggers")
	if entries, err := os.ReadDir(triggersDir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if name == "File" || name == "Unincorp" || name == "Lock" {
				continue
			}
			os.Truncate(filepath.Join(triggersDir, name), 0) //nolint:errcheck
		}
	}

	// The dpkg database is session-scoped: it runs on the tmpfs copied from the host.
	// Not persisted: "half-configured" state between sessions would corrupt later
	// installs. Package installations persist via --instdir=pkgroot (on disk).

	// The apt lists come from the host and may not match the guest's
	// Debian sources.list (e.g. host is Ubuntu/Vanilla OS).
	// Always clear them: apt-get update recreates them in seconds.
	invalidateAptLists(varDst) //nolint:errcheck

	return nil
}

// bindHome mounts the user's home directory as read-write in the guest.
// bindHome gives the guest its OWN persistent home and shares back only the
// user's DATA directories from the real home.
//
// The threat is auto-injection, NOT data: the host automatically executes a
// small, known set of files (~/.bashrc and other shell rc, ~/.config/autostart,
// ~/.config/systemd/user, ~/.config/environment.d, ~/.local/bin on PATH, ...).
// If the guest could write those in the real home they would run OUTSIDE the
// sandbox as the host user. So the guest gets an isolated home (under ush
// storage) where its dotfiles, shell rc and systemd --user units live and
// persist, but which the host NEVER reads. The real home is not mounted.
//
// The user's data is a different matter: documents do not auto-execute, and you
// WANT changes to flow back to the host. So we bind the real XDG user dirs
// (Documents, Downloads, ...) and the launch directory RW into the guest home.
// This is an allow-list (default-deny): a data dir we miss is merely "not
// shared", never an escape, whereas a missed auto-injection path in a deny-list
// would be game over.
func (g *GuestFS) bindHome() error {
	if g.HomeDir == "" {
		return nil
	}
	dst := filepath.Join(g.GuestRoot, g.HomeDir)

	// 1. The isolated, persistent guest home. It lives under ush storage, OUTSIDE
	//    the real home, so the guest also cannot reach ush's own policy/layers.
	//    ush and dsh use distinct homes (home vs dev-home).
	guestHome := filepath.Join(g.LayerDir, "persistent", g.persistentHomeName())
	fresh := false
	if _, err := os.Stat(guestHome); os.IsNotExist(err) {
		fresh = true
	}
	if err := os.MkdirAll(guestHome, 0700); err != nil {
		return fmt.Errorf("fs: guest home: %w", err)
	}
	if fresh {
		// Seed innocuous dotfiles from /etc/skel so the first session is not bare.
		// Auto-injection files placed here only ever run INSIDE the guest.
		_ = copyDirContents("/etc/skel", guestHome)
	}
	if err := bindMount(guestHome, dst, false); err != nil {
		return fmt.Errorf("fs: bind guest home: %w", err)
	}

	// 2. Expose the real home DATA dirs, write-isolated by default (the
	//    ChromeOS/Crostini model). The guest READS the host directory but every
	//    write diverges into a guest-private overlay: nothing it writes reaches
	//    the real host tree, and nothing it drops there can be built or executed
	//    by the host. This closes the whole "guest writes what the host later
	//    runs" class (git hooks, a planted *_test.go the owner builds, a 0755
	//    file the owner runs) by construction, not with per-syscall hooks.
	//
	//    A directory the user explicitly trusts via `perm trust-dir` is NOT
	//    handled here: it is bound raw read-write by bindTrustedDevDirs (full
	//    host access, on purpose), the "Share with Linux" opt-in.
	for _, sub := range g.sharedHomeSubdirs() {
		src := filepath.Join(g.HomeDir, sub)
		fi, err := os.Stat(src)
		if err != nil || !fi.IsDir() {
			continue
		}
		if g.isTrustedDevDir(src) {
			continue // bound raw read-write by bindTrustedDevDirs
		}
		dstSub := filepath.Join(dst, sub)
		if err := g.overlayExpose(src, dstSub); err != nil {
			// Fail safe: read-only, NEVER raw read-write.
			ushlog.Warn("fs: share overlay failed, falling back to read-only", "dir", sub, "err", err)
			if e2 := bindMount(src, dstSub, true); e2 != nil {
				ushlog.Warn("fs: share read-only fallback failed", "dir", sub, "err", e2)
			}
		}
	}

	ushlog.Info("fs: isolated guest home; real data dirs write-isolated (overlay), trust-dir for full access",
		"home", g.HomeDir)
	return nil
}

// isTrustedDevDir reports whether host path p is at or below a user-trusted
// developer directory.
func (g *GuestFS) isTrustedDevDir(p string) bool {
	p = filepath.Clean(p)
	for _, d := range g.TrustedDevDirs {
		d = filepath.Clean(d)
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// bindTrustedDevDirs binds each user-confirmed developer directory read-write
// straight from the host, with NO VCS-metadata isolation: the user has vouched
// for it and wants to build, run and commit there normally. These dirs are also
// reported to the supervisor as exec-strip exemptions, so executables created
// here stay runnable. Granting them is gated by a host-side broker confirmation,
// so a compromised guest cannot expose arbitrary host paths to itself.
func (g *GuestFS) bindTrustedDevDirs() error {
	for _, dir := range g.TrustedDevDirs {
		dir = filepath.Clean(dir)
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			ushlog.Warn("fs: trusted dev dir missing, skipping", "dir", dir)
			continue
		}
		dst := filepath.Join(g.GuestRoot, dir)
		if err := os.MkdirAll(dst, 0755); err != nil {
			ushlog.Warn("fs: trusted dev dir mkdir failed", "dir", dir, "err", err)
			continue
		}
		if err := bindMount(dir, dst, false); err != nil {
			ushlog.Warn("fs: trusted dev dir bind failed", "dir", dir, "err", err)
			continue
		}
		ushlog.Info("fs: trusted dev dir bound (full host access)", "dir", dir)
	}
	return nil
}

// HostBackedRWGuestPaths returns the guest-absolute paths that are bound RAW
// read-write straight from the host, i.e. where a guest write lands on a real
// host file the host could later run. The supervisor strips the executable bit
// from anything the guest makes executable under them.
//
// With the home data dirs write-isolated by default (overlay), the only raw
// host read-write surface left is an explicit `:rw` extra bind. The shared data
// dirs are overlays (writes diverge into a guest-private layer, so they cannot
// produce a host-runnable file and need no stripping), and trusted dev dirs are
// full-access on purpose (exempt). The guest's own private areas are likewise
// never listed.
func (g *GuestFS) HostBackedRWGuestPaths() []string {
	var out []string
	for _, spec := range g.ExtraBinds {
		parts := strings.Split(strings.TrimSpace(spec), ":")
		if len(parts) >= 3 && parts[2] == "rw" && parts[1] != "" {
			out = append(out, parts[1])
		}
	}
	return out
}

// bindPkgLayer re-exposes the package install root (pkgroot) into the guest.
// `pkg install` puts binaries under <storage>/layers/persistent/pkgroot, which
// lives below the real home, now hidden by the isolated guest home. Without
// this rebind, pkg-installed apps (e.g. `code`) vanish from PATH even though
// they are installed. Only the pkgroot subtree is exposed, RW so installs keep
// working; ush's policy/audit/layers state stays out of the guest.
func (g *GuestFS) bindPkgLayer() error {
	src := filepath.Join(g.LayerDir, "persistent", "pkgroot")
	if _, err := os.Stat(src); err != nil {
		return nil // nothing installed yet
	}
	dst := filepath.Join(g.GuestRoot, src)
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("fs: pkgroot mkdir: %w", err)
	}
	if err := bindMount(src, dst, false); err != nil {
		return fmt.Errorf("fs: bind pkgroot: %w", err)
	}
	ushlog.Info("fs: pkg layer exposed to guest", "pkgroot", src)
	return nil
}

// applyExtraBinds mounts the user-declared host paths into the guest. Each entry
// is "host_path:guest_path[:MODE]".
//
// The guest is less trusted than the host, yet a plain read-write bind lets it
// modify host files that host-privileged code may later read or EXECUTE (config
// dirs, hooks, plugin trees, autostart, ...). That is a generic sandbox -> host
// escape, not specific to any one app: the openat broker only mediates /dev/*,
// so writes to any host-backed mount are otherwise unmediated. So the SAFE
// behaviour is the DEFAULT and raw host writes must be opted into explicitly:
//
//   - (default)  directories are write-isolated via overlay: the guest reads the
//     whole host tree but every write diverges into a guest-private
//     upper layer, so the host directory is NEVER modified, whatever
//     path the guest targets. Files default to read-only. This closes
//     the write surface by construction, not path by path.
//   - ro         read-only bind (run/read host files, never modify them).
//   - rw         EXPLICIT raw read-write into the host. The guest can modify host
//     files; only use it for data you intentionally want written back
//     to the host. Logged loudly.
//
// If an overlay cannot be mounted (e.g. the host tree contains nested mounts) we
// fall back to read-only, never to writable. It runs after bindHome so binds onto
// paths inside the (isolated) guest home land correctly.
func (g *GuestFS) applyExtraBinds() error {
	for _, spec := range g.ExtraBinds {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		parts := strings.Split(spec, ":")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			ushlog.Warn("fs: bad extra bind, want host:guest[:ro|:rw]", "spec", spec)
			continue
		}
		src, guestPath := parts[0], parts[1]
		mode := "default"
		if len(parts) >= 3 && parts[2] != "" {
			mode = parts[2]
		}
		// "overlay" is accepted as an explicit spelling of the default.
		if mode == "overlay" {
			mode = "default"
		}

		fi, err := os.Stat(src)
		if err != nil {
			ushlog.Warn("fs: extra bind source missing, skipping", "src", src, "err", err)
			continue
		}
		dst := filepath.Join(g.GuestRoot, guestPath)

		// Directories: default to write-isolated overlay; rw/ro on request.
		if fi.IsDir() {
			switch mode {
			case "rw":
				os.MkdirAll(dst, 0755)
				if err := bindMount(src, dst, false); err != nil {
					ushlog.Warn("fs: extra bind failed", "src", src, "guest", guestPath, "err", err)
					continue
				}
				ushlog.Warn("fs: extra bind is RAW read-write into the host; guest can modify host files",
					"src", src, "guest", guestPath)
			case "ro":
				os.MkdirAll(dst, 0755)
				if err := bindMount(src, dst, true); err != nil {
					ushlog.Warn("fs: extra bind failed", "src", src, "guest", guestPath, "err", err)
					continue
				}
				ushlog.Info("fs: extra bind applied (ro)", "src", src, "guest", guestPath)
			default:
				if err := g.overlayExpose(src, dst); err != nil {
					// Fail safe: read-only, never writable.
					ushlog.Warn("fs: overlay failed, falling back to read-only", "src", src, "err", err)
					os.MkdirAll(dst, 0755)
					if e2 := bindMount(src, dst, true); e2 != nil {
						ushlog.Warn("fs: extra bind ro fallback failed", "src", src, "err", e2)
						continue
					}
				}
				ushlog.Info("fs: extra bind applied (write-isolated, host read-only)", "src", src, "guest", guestPath)
			}
			continue
		}

		// Files: default read-only (overlay is directory-only); rw on request.
		ro := mode != "rw"
		os.MkdirAll(filepath.Dir(dst), 0755)
		if f, e := os.OpenFile(dst, os.O_CREATE, 0644); e == nil {
			f.Close()
		}
		if err := bindMount(src, dst, ro); err != nil {
			ushlog.Warn("fs: extra bind failed", "src", src, "guest", guestPath, "err", err)
			continue
		}
		if !ro {
			ushlog.Warn("fs: extra file bind is RAW read-write into the host", "src", src, "guest", guestPath)
		} else {
			ushlog.Info("fs: extra file bind applied (ro)", "src", src, "guest", guestPath)
		}
	}
	return nil
}

// overlayExpose mounts an overlayfs at dst whose lower layer is the host
// directory lower (read-only) and whose upper/work layers are private to the
// guest. The guest sees and reads the entire host tree, but every write diverges
// into the guest-private upper layer: the host directory is NEVER modified, no
// matter which path under it the guest writes. This closes a whole class of
// "guest writes what host-privileged code later executes" escapes by
// construction, instead of enumerating individual dangerous paths (a denylist
// that can always be defeated by a host-config layout we did not anticipate,
// e.g. hooks/, settings*.json, plugins/, marketplaces/, cache/).
//
// The upper/work layers live under the persistent layer so the guest's own state
// (sessions, history) survives across runs; anything malicious it writes there
// stays guest-private and only ever runs inside the guest.
func (g *GuestFS) overlayExpose(lower, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	key := strings.Trim(strings.ReplaceAll(strings.TrimPrefix(dst, g.GuestRoot), "/", "_"), "_")
	base := filepath.Join(g.LayerDir, "persistent", "overlay", key)
	upper := filepath.Join(base, "upper")
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(upper, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(work, 0755); err != nil {
		return err
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	if err := unix.Mount("overlay", dst, "overlay", 0, opts); err != nil {
		return fmt.Errorf("overlay mount %s: %w", dst, err)
	}
	return nil
}

// sharedHomeSubdirs returns the top-level directories of the real home to expose
// into the guest home. Because ush is a shell and the user navigates the whole
// home with `cd`, this is EVERY non-dot top-level directory (Projects, Documents,
// Downloads, code, ...), not a fixed XDG list: the user must see real files
// wherever they cd.
//
// The single structural rule is "skip dotfiles/dotdirs": ~/.ssh, ~/.gnupg,
// ~/.aws (secrets) and ~/.bashrc, ~/.config/autostart, ~/.config/systemd/user
// (auto-execution surface) stay the guest's own, never the host's. One rule, not
// a growing denylist. Everything returned here is exposed write-isolated
// (overlay) by bindHome; `perm trust-dir` opts a subtree into full read-write.
func (g *GuestFS) sharedHomeSubdirs() []string {
	if g.HomeDir == "" {
		return nil
	}
	entries, err := os.ReadDir(g.HomeDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue // the home secrets + auto-injection surface stays private
		}
		// Only directories; loose files in the home root stay private. Resolve
		// symlinks so a symlinked data dir still counts as a directory.
		info, statErr := os.Stat(filepath.Join(g.HomeDir, name))
		if statErr != nil || !info.IsDir() {
			continue
		}
		out = append(out, name)
	}
	return out
}

// bindDevices mounts necessary device files in the guest.
// deviceBind is one host device node (or dir) to expose in the guest /dev.
type deviceBind struct {
	src, dst string
	ro       bool
}

// touch creates an empty file at path (a bind target), reporting success.
func touch(path string) bool {
	f, err := os.OpenFile(path, os.O_CREATE, 0666)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func (g *GuestFS) bindDevices() error {
	dev := filepath.Join(g.GuestRoot, "dev")
	binds := []deviceBind{
		{"/dev/null", filepath.Join(dev, "null"), false},
		{"/dev/zero", filepath.Join(dev, "zero"), false},
		{"/dev/full", filepath.Join(dev, "full"), false},
		{"/dev/urandom", filepath.Join(dev, "urandom"), false},
		{"/dev/random", filepath.Join(dev, "random"), false},
		{"/dev/tty", filepath.Join(dev, "tty"), false},
	}

	// Developer (dsh) profile: expose /dev/fuse so fuse-overlayfs (the storage
	// driver rootless podman uses) works inside the dev world.
	if g.DevProfile {
		if _, err := os.Stat("/dev/fuse"); err == nil {
			fuseDst := filepath.Join(dev, "fuse")
			touch(fuseDst)
			binds = append(binds, deviceBind{"/dev/fuse", fuseDst, false})
		}
	}

	g.setupDevpts()

	// TUN/TAP: needed for pasta network.
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		tunDir := filepath.Join(dev, "net")
		os.MkdirAll(tunDir, 0755)
		tunDst := filepath.Join(tunDir, "tun")
		if touch(tunDst) {
			binds = append(binds, deviceBind{"/dev/net/tun", tunDst, false})
		}
	}

	// GPU: bind /dev/dri if present.
	if _, err := os.Stat("/dev/dri"); err == nil {
		binds = append(binds, deviceBind{"/dev/dri", filepath.Join(dev, "dri"), false})
	}

	// Audio: bind /dev/snd if present.
	if _, err := os.Stat("/dev/snd"); err == nil {
		sndDst := filepath.Join(dev, "snd")
		os.MkdirAll(sndDst, 0755)
		binds = append(binds, deviceBind{"/dev/snd", sndDst, false})
	}

	for _, b := range binds {
		fi, err := os.Lstat(b.src)
		if os.IsNotExist(err) {
			continue
		}
		if fi != nil && !fi.IsDir() {
			touch(b.dst)
		}
		if err := bindMount(b.src, b.dst, b.ro); err != nil {
			ushlog.Warn("fs: bind device failed", "src", b.src, "err", err)
		}
	}

	g.setupDevShm()
	return nil
}
