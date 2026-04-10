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
