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

	// usrOverlaid is set by setupUsr when it mounts the per-subdir /usr overlays.
	// setupBinBash then skips its own /bin overlay: /bin is a symlink to usr/bin, so
	// a separate /bin overlay would land on /usr/bin and shadow the dedicated /usr/bin
	// overlay (hiding installed files like /usr/bin/perl). bash is seeded into
	// pkgroot/usr/bin instead, surfaced by the /usr/bin overlay through the symlink.
	usrOverlaid bool

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
	// After the pkgroot is exposed, overlay /usr so installed dev headers/libs (in
	// pkgroot/usr) show at their absolute paths /usr/include, /usr/lib (#74).
	if err := g.setupUsr(); err != nil {
		return err
	}
	// Expose /bin/bash so Debian packages' #!/bin/bash scripts can exec (bash is
	// Essential, so apt never installs it; the base is BusyBox-only).
	if err := g.setupBinBash(); err != nil {
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

// setupBinBash exposes a real bash at the absolute /bin/bash that Debian package
// maintainer scripts and installed programs assume (#!/bin/bash). The Sinty base
// /bin is BusyBox-only and bind-mounted read-only, so overlay /bin with a writable
// upper carrying a bash staged from ToolsDir. bash's Debian shared libs (libc,
// libtinfo) resolve via the same guest-leading LD_LIBRARY_PATH the apt tools use,
// inherited by anything the shell execs. Best-effort: on any failure the guest
// keeps its BusyBox /bin so /bin/sh scripts still work.
func (g *GuestFS) setupBinBash() error {
	if g.ToolsDir == "" {
		return nil
	}
	// When setupUsr mounted the per-subdir /usr overlays, bash was already seeded into
	// pkgroot/usr/bin and is surfaced by the dedicated /usr/bin overlay (reached at
	// /bin/bash via the /bin -> usr/bin symlink). A separate /bin overlay here would
	// resolve /bin to usr/bin and mount ON TOP of that dedicated overlay, shadowing it
	// and hiding installed files like /usr/bin/perl. So skip it in that case.
	if g.usrOverlaid {
		ushlog.Info("fs: /bin bash overlay skipped (bash seeded into pkgroot/usr/bin, surfaced by /usr/bin overlay)")
		return nil
	}
	var bashSrc string
	for _, p := range []string{
		filepath.Join(g.ToolsDir, "bin", "bash"),
		filepath.Join(g.ToolsDir, "usr", "bin", "bash"),
	} {
		if _, err := os.Stat(p); err == nil {
			bashSrc = p
			break
		}
	}
	if bashSrc == "" {
		return nil // bash not bootstrapped; nothing to expose
	}
	data, err := os.ReadFile(bashSrc)
	if err != nil {
		return nil
	}
	upper := filepath.Join(g.LayerDir, ".bin-overlay-upper")
	work := filepath.Join(g.LayerDir, ".bin-overlay-work")
	if err := os.MkdirAll(upper, 0o755); err != nil {
		return nil
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil
	}
	if err := os.WriteFile(filepath.Join(upper, "bash"), data, 0o755); err != nil {
		return nil
	}
	dst := filepath.Join(g.GuestRoot, "bin")
	opts := fmt.Sprintf("lowerdir=/bin,upperdir=%s,workdir=%s,userxattr", upper, work)
	if err := unix.Mount("overlay", dst, "overlay", 0, opts); err == nil {
		ushlog.Info("fs: /bin overlaid with bash (#!/bin/bash scripts runnable)")
		return nil
	}
	opts = fmt.Sprintf("lowerdir=/bin,upperdir=%s,workdir=%s", upper, work)
	if err := unix.Mount("overlay", dst, "overlay", 0, opts); err == nil {
		ushlog.Info("fs: /bin overlaid with bash")
		return nil
	} else {
		ushlog.Info("fs: /bin kernel overlay unavailable, trying fuse-overlayfs", "err", err)
	}
	// Same overlay-root constraint as /usr: on Sinty the kernel driver refuses, so
	// #!/bin/bash scripts would not run. fuse-overlayfs merges bash over BusyBox /bin.
	if g.fuseOverlay("/bin", "/bin", upper, filepath.Join(g.LayerDir, ".bin-fuse-work"), dst) {
		ushlog.Info("fs: /bin overlaid with bash via fuse-overlayfs (#!/bin/bash scripts runnable)")
		return nil
	}
	ushlog.Warn("fs: /bin bash overlay failed (bash scripts may not run)")
	return nil
}

// setupUsr is a no-op: /usr is bind-mounted RO by bindRODirs().
// Packages are installed into pkgPrefix (via dpkg --instdir) instead
// of /usr, so /usr can stay read-only.
func (g *GuestFS) setupUsr() error {
	// dsh developer shell: apt installs headers/libs into <pkgroot>/usr/{include,lib,...},
	// but gcc/ld search /usr/include, /usr/lib absolutely (and the glibc linker scripts use
	// absolute paths), so with the plain bind-RO /usr from bindRODirs the installed dev files
	// are invisible and C will not compile or link. Overlay /usr: lower = host /usr (RO system
	// headers/libs/crt), upper = pkgroot/usr (apt's RW install target). The two merge, so an
	// installed toolchain resolves everything at the absolute paths. Same mechanics as /etc
	// and /var. Safe fallback: on any failure the guest keeps the working bind-RO /usr
	// (dev-compile just unavailable), never a dead guest.
	guestPkgroot := filepath.Join(g.GuestRoot, g.LayerDir, "persistent", "pkgroot")
	barePkgroot := filepath.Join(g.LayerDir, "persistent", "pkgroot")
	pkgroot := ""
	if fi, err := os.Stat(filepath.Join(guestPkgroot, "usr")); err == nil && fi.IsDir() {
		pkgroot = guestPkgroot
	} else if fi, err := os.Stat(filepath.Join(barePkgroot, "usr")); err == nil && fi.IsDir() {
		pkgroot = barePkgroot
	}
	if pkgroot == "" {
		ushlog.Info("fs: /usr overlay skipped (pkgroot/usr not present)",
			"guestPkgUsr", filepath.Join(guestPkgroot, "usr"),
			"barePkgUsr", filepath.Join(barePkgroot, "usr"),
			"layerDir", g.LayerDir, "guestRoot", g.GuestRoot, "homeDir", g.HomeDir)
		return nil
	}
	pkgUsr := filepath.Join(pkgroot, "usr")
	if err := os.MkdirAll(pkgUsr, 0o755); err != nil {
		ushlog.Warn("fs: pkgroot/usr create failed, keeping bind-RO /usr", "pkgUsr", pkgUsr, "err", err)
		return nil
	}
	// Seed the FHS skeleton and the pure-perl infrastructure (perl-base, debconf, bash)
	// into the upper BEFORE the overlays mount. dpkg installs with --instdir=pkgroot
	// (raw writes into the guest-owned pkgroot: no rootless copy-up, no write wall), and
	// the dedicated per-subdir overlays surface the installed files at their absolute
	// /usr paths. The one class the overlay cannot surface is a deep dir a package
	// creates BEHIND the mount and re-reads in the same session - debconf's Debconf::
	// modules are exactly that. So debconf is treated as INFRASTRUCTURE (baked into the
	// tools tree) and pre-seeded here alongside perl-base, present and visible before
	// any package's maintainer script runs.
	g.seedUsrSkeleton(pkgUsr)
	g.seedPerlBase(pkgUsr)
	g.seedDebconfBase(pkgUsr)
	g.seedBash(pkgUsr)

	// One DEDICATED, non-aliased fuse-overlayfs per top-level /usr subdir: lower=/usr/<X>,
	// upper=pkgroot/usr/<X>, so each pkgroot/usr/<X> is the upperdir of exactly ONE
	// overlay. This is the proven /bin bash pattern (a mapped-owned file in the upper
	// merges over the nobody-owned erofs lower and becomes visible) generalised to /usr.
	// dpkg installs with --instdir=pkgroot (writing raw into pkgroot/usr/<X>, which the
	// guest owns, so no copy-up and no rootless write wall); the dedicated overlay then
	// surfaces those files at the absolute /usr/<X> path the same session. The earlier
	// single big /usr overlay left upper files in in-both subdirs invisible because its
	// upper aliased the dedicated overlays' uppers; giving each subdir its own overlay
	// removes that aliasing. fuse-overlayfs is required (the kernel driver refuses on the
	// overlay-root host); it opens /dev/fuse before pivot.
	entries, err := os.ReadDir("/usr")
	if err != nil {
		ushlog.Warn("fs: cannot enumerate /usr for per-subdir overlays, keeping bind-RO /usr", "err", err)
		return nil
	}
	overlaid := 0
	for _, e := range entries {
		if !e.IsDir() { // skip symlinks (e.g. /usr/lib64 -> lib) and files
			continue
		}
		if g.overlayUsrSubdir(pkgroot, pkgUsr, e.Name()) {
			overlaid++
		}
	}
	if overlaid > 0 {
		g.usrOverlaid = true // setupBinBash skips its colliding /bin overlay
	}
	ushlog.Info("fs: /usr per-subdir dedicated overlays mounted", "pkgroot", pkgroot, "count", overlaid)
	return nil
}

// seedBash copies the staged bash interpreter from the tools dir into the pkgroot
// upper (pkgUsr/bin), so /usr/bin/bash exists at overlay mount time and is surfaced
// by the dedicated /usr/bin overlay (reached at /bin/bash via the /bin -> usr/bin
// symlink). This replaces the standalone /bin overlay, which would otherwise land on
// /usr/bin (through the symlink) and shadow the dedicated overlay. bash's Debian libs
// resolve via the same guest-leading LD_LIBRARY_PATH the apt tools use.
func (g *GuestFS) seedBash(pkgUsr string) {
	if g.ToolsDir == "" {
		return
	}
	toolsUsr := filepath.Join(g.GuestRoot, g.ToolsDir, "usr")
	var bashSrc string
	for _, p := range []string{
		filepath.Join(g.GuestRoot, g.ToolsDir, "bin", "bash"),
		filepath.Join(toolsUsr, "bin", "bash"),
	} {
		if _, err := os.Stat(p); err == nil {
			bashSrc = p
			break
		}
	}
	if bashSrc == "" {
		return
	}
	dst := filepath.Join(pkgUsr, "bin", "bash")
	if _, err := os.Stat(dst); err == nil {
		return // already seeded (pkgroot persists)
	}
	data, err := os.ReadFile(bashSrc)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Join(pkgUsr, "bin"), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(dst, data, 0o755); err == nil {
		ushlog.Info("fs: seeded bash into pkgroot (/usr/bin/bash, reached at /bin/bash via symlink)")
	}
}

// overlayUsrSubdir mounts a dedicated fuse-overlayfs on /usr/<sub>, lower=/usr/<sub>
// (the read-only erofs subdir, owned by nobody in the guest) and upper=pkgroot/usr/<sub>
// (where dpkg installs with --instdir=pkgroot). Each pkgroot/usr/<sub> is the upperdir
// of exactly ONE overlay, so there is no aliasing: a mapped-owned upper file merges over
// the nobody-owned lower and is surfaced at the absolute /usr/<sub> path, the same way
// the proven /bin bash overlay surfaces bash over BusyBox /bin. Best-effort: returns
// true when mounted, false (guest keeps the bind-RO /usr/<sub>) on any failure.
func (g *GuestFS) overlayUsrSubdir(pkgroot, pkgUsr, sub string) bool {
	upper := filepath.Join(pkgUsr, sub)
	if err := os.MkdirAll(upper, 0o755); err != nil {
		return false
	}
	dst := filepath.Join(g.GuestRoot, "usr", sub)
	work := filepath.Join(pkgroot, ".usr"+sub+"-fuse-work")
	if g.fuseOverlay("/usr/"+sub, "/usr/"+sub, upper, work, dst) {
		ushlog.Info("fs: /usr/"+sub+" dedicated overlay (installed files visible in merged view)", "upper", upper)
		return true
	}
	return false
}

// fuseOverlay merges upper over lower at dst using fuse-overlayfs, the user-space
// overlay. It runs unprivileged in the guest and succeeds where the in-kernel
// overlay driver returns EPERM on an overlay-root host (Sinty's immutable
// erofs+dm-verity+tmpfs). label names the mountpoint for logs. Returns true when
// the merged tree is mounted.
func (g *GuestFS) fuseOverlay(label, lower, upper, work, dst string, extraOpts ...string) bool {
	bin, err := exec.LookPath("fuse-overlayfs")
	if err != nil {
		// PATH may be minimal during setup; fall back to the image's fixed path.
		if _, statErr := os.Stat("/usr/bin/fuse-overlayfs"); statErr != nil {
			ushlog.Warn("fs: fuse-overlayfs not found", "mount", label, "err", err)
			return false
		}
		bin = "/usr/bin/fuse-overlayfs"
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		ushlog.Warn("fs: fuse-overlayfs workdir failed", "mount", label, "work", work, "err", err)
		return false
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	for _, e := range extraOpts {
		opts += "," + e
	}
	out, err := exec.Command(bin, "-o", opts, dst).CombinedOutput()
	if err != nil {
		ushlog.Warn("fs: fuse-overlayfs failed", "mount", label,
			"err", err, "out", strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// setupEtc populates the guest /etc from the host by copying into a tmpfs so
// maintainer scripts can write to it. It does not use overlayfs because /etc may
// already be overlayfs (which cannot be stacked in a user namespace) on
// immutable, overlay-root hosts.
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
	// On non-Debian hosts this file doesn't exist.
	ensureDebconfConf(etcDst)

	// Ensure a valid Debian sources.list in the guest.
	// On non-Debian systems there is no sources.list.
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
// at least one valid Debian entry. On non-Debian systems
// there is no sources.list, so apt finds no packages.
// Returns true if it created/replaced the sources.list (lists must be re-downloaded).
func ensureDebianSources(aptDir string) bool {
	os.MkdirAll(aptDir, 0755) //nolint:errcheck
	sourcesList := filepath.Join(aptDir, "sources.list")

	// The Debian archive keyring and gpgv are staged into the guest exec dir
	// (blockPackageManagers), so [signed-by=...] lets apt authenticate InRelease.
	const keyring = "/run/ush/exec/keyrings/debian-archive-keyring.gpg"

	// ALWAYS purge sources.list.d first, before any early return. apt reads every
	// *.list and *.sources (deb822) file there, so an attacker-planted
	// evil.sources would bypass whatever we enforce on sources.list. The pkg
	// manager also passes Dir::Etc::sourceparts=/dev/null as defence-in-depth.
	changed := false
	sourcesD := filepath.Join(aptDir, "sources.list.d")
	if entries, err := os.ReadDir(sourcesD); err == nil {
		for _, e := range entries {
			p := filepath.Join(sourcesD, e.Name())
			if rerr := os.RemoveAll(p); rerr != nil {
				// Fail closed: if we cannot remove it, neutralise its content so it
				// cannot define a repo, and warn loudly if even that fails.
				if werr := os.WriteFile(p, nil, 0644); werr != nil {
					ushlog.Warn("fs: SECURITY could not purge sources.list.d entry", "path", p, "err", werr)
					continue
				}
			}
			changed = true
		}
		if changed {
			ushlog.Info("fs: sources.list.d purged (extra/host repos removed)")
		}
	}

	// apt.conf.d must exist and be empty. apt loads it while initialising its
	// config, before it parses the command line, so Dir::Etc::parts=/dev/null
	// arrives too late to suppress either the drop-ins or the
	// "Unable to read /etc/apt/apt.conf.d/ - DirectoryExists" warning on every
	// install. Existing entries get the sources.list.d treatment: they are read
	// ahead of our -o flags and could set what those do not pin (e.g.
	// APT::Get::AllowUnauthenticated).
	confD := filepath.Join(aptDir, "apt.conf.d")
	if entries, err := os.ReadDir(confD); err == nil {
		for _, e := range entries {
			p := filepath.Join(confD, e.Name())
			if rerr := os.RemoveAll(p); rerr != nil {
				if werr := os.WriteFile(p, nil, 0644); werr != nil {
					ushlog.Warn("fs: SECURITY could not purge apt.conf.d entry", "path", p, "err", werr)
				}
			}
		}
	} else if err := os.MkdirAll(confD, 0755); err != nil {
		ushlog.Warn("fs: unable to create apt.conf.d", "path", confD, "err", err)
	}

	// Keep an existing sources.list ONLY if EVERY deb/deb-src line is verified
	// against our staged keyring. Returning early on any `deb ` line (the old
	// behaviour) let a pre-existing or attacker-planted
	// `deb [trusted=yes] http://evil ...` survive and silently bypass signed-by.
	// Parse options case-insensitively and whitespace-tolerantly so a crafted
	// `[signed-by=<ours> Trusted=yes]` or `[ trusted=yes ]` cannot slip past.
	if data, err := os.ReadFile(sourcesList); err == nil {
		sawDeb, allSafe := false, true
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "deb ") && !strings.HasPrefix(line, "deb-src ") {
				continue
			}
			sawDeb = true
			opts := ""
			if i := strings.Index(line, "["); i >= 0 {
				if j := strings.Index(line[i:], "]"); j >= 0 {
					opts = line[i : i+j+1]
				}
			}
			low := strings.ToLower(strings.NewReplacer(" ", "", "\t", "").Replace(opts))
			unsafe := strings.Contains(low, "trusted=yes") ||
				strings.Contains(low, "allow-insecure=yes") ||
				strings.Contains(low, "allow-downgrade-to-insecure=yes")
			// signed-by must appear EXACTLY once and be EXACTLY our keyring. apt
			// matches the option name case-insensitively and treats the value as a
			// comma list, so reject duplicates (`signed-by=/ours Signed-By=/evil`),
			// mixed case, quotes, and appended keyrings.
			optsLow := strings.ToLower(opts)
			signedOK := false
			if strings.Count(optsLow, "signed-by=") == 1 {
				i := strings.Index(optsLow, "signed-by=")
				val := opts[i+len("signed-by="):] // original case: it is a path
				if e := strings.IndexAny(val, " \t]"); e >= 0 {
					val = val[:e]
				}
				val = strings.Trim(val, "\"'")
				signedOK = val == keyring
			}
			if unsafe || !signedOK {
				allSafe = false
				break
			}
		}
		if sawDeb && allSafe {
			return changed // already signature-verified against our keyring, keep
		}
		if sawDeb {
			ushlog.Warn("fs: replacing unverified apt sources.list (trusted=yes or missing signed-by)")
		}
	}

	// Create sources.list pointing to Debian bookworm, signature-verified.
	// Pin bookworm so the suite matches the bootstrapped apt/gpgv and the staged
	// keyring; "stable" now floats to trixie, whose signing key is absent from
	// the bookworm keyring, which would fail verification.
	content := "deb [signed-by=" + keyring + "] http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware\n" +
		"deb [signed-by=" + keyring + "] http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware\n"
	if err := os.WriteFile(sourcesList, []byte(content), 0644); err != nil {
		ushlog.Warn("fs: unable to create Debian sources.list", "err", err)
		return changed
	}
	ushlog.Info("fs: Debian sources.list created (non-Debian system detected)")
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
	// The leading global stanza (Config:/Templates:/Frontend:) is REQUIRED: it tells
	// debconf which named database to use for config data and templates. Without it,
	// Debconf::Config parses the first driver stanza (Name: config ...) AS the global
	// stanza and dies "Attempt to access disallowed key 'name' in a restricted hash"
	// (the global config is a fields-restricted hash that has no 'name' key), which
	// aborts every debconf maintainer script. Frontend: Noninteractive matches the
	// DEBIAN_FRONTEND=noninteractive install and avoids any dialog/readline driver.
	const debconfConf = `# Debconf configuration for USH guest environment
# Minimal noninteractive config - generated by USH
Config: config
Templates: template
Frontend: Noninteractive

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

// seedUsrSkeleton creates a generous FHS directory skeleton inside the pkgroot
// (the /usr overlay's upperdir) BEFORE the overlay is mounted. Any directory
// present in the upper at mount time is part of the merged view, so the raw files
// dpkg (and the LD_PRELOAD shim that redirects the maintainer scripts' /usr writes
// to pkgroot) later write into these dirs are visible at the absolute /usr path in
// the same session. Without this, a package that installs into a directory the
// busybox base lacks (e.g. /usr/share/debconf) creates that dir behind the mounted
// overlay, which the merged view never surfaces, so the maintainer script's read of
// /usr/share/debconf/confmodule (or exec of frontend) fails. The critical entry is
// /usr/share/debconf; the rest cover the common install targets. A package that
// creates a genuinely new deep dir not listed here still lands invisible (the known
// bound of this approach), but the files maintainer scripts read back in-session
// almost always live under /usr/share/debconf, which is covered.
func (g *GuestFS) seedUsrSkeleton(pkgUsr string) {
	dirs := []string{
		"share/debconf",
		"lib", "lib/x86_64-linux-gnu", "bin", "sbin", "include",
		"share", "share/doc", "share/man", "share/locale", "share/fontconfig",
		"share/applications", "share/icons", "share/misc", "share/pkgconfig",
	}
	for _, d := range dirs {
		os.MkdirAll(filepath.Join(pkgUsr, d), 0o755) //nolint:errcheck
	}
	ushlog.Info("fs: seeded FHS skeleton into pkgroot/usr (maintainer scripts see files in pre-existing dirs)")
}

// copyFileIfExists copies src to dst if src exists; ignores errors.
// seedPerlBase copies the staged perl-base interpreter and its module tree from
// the tools dir into the pkgroot upper (pkgUsr), so /usr/bin/perl exists in the
// guest. debconf's frontend is a #!/usr/bin/perl script and every debconf
// maintainer script sources it; without perl they die with exit 127. perl-base
// alone suffices: debconf declares it as its only dependency and its Debconf::
// modules ship with the debconf package installed into the same pkgroot.
func (g *GuestFS) seedPerlBase(pkgUsr string) {
	if g.ToolsDir == "" {
		return
	}
	// seedPerlBase runs PRE-pivot (Setup's pivot_root is last), and bindRODirs
	// mounted the base /usr (which carries the pre-baked tools tree) under
	// GuestRoot/usr, not at the absolute /usr of the guest namespace (still empty
	// pre-pivot). g.ToolsDir is an absolute path (/usr/share/ush/tools); read it
	// GuestRoot-relative so the stat resolves against the mounted tools, exactly as
	// pkgUsr (the write target) is already GuestRoot-relative.
	toolsUsr := filepath.Join(g.GuestRoot, g.ToolsDir, "usr")
	if _, err := os.Stat(filepath.Join(toolsUsr, "bin", "perl")); err != nil {
		ushlog.Debug("fs: perl-base not staged in tools, /usr/bin/perl unavailable", "toolsUsr", toolsUsr)
		return
	}
	if _, err := os.Stat(filepath.Join(pkgUsr, "bin", "perl")); err == nil {
		return // already seeded in a prior session (pkgroot persists)
	}
	seed := func(rel string) {
		src := filepath.Join(toolsUsr, rel)
		fi, err := os.Stat(src)
		if err != nil {
			return
		}
		dst := filepath.Join(pkgUsr, rel)
		if fi.IsDir() {
			os.MkdirAll(dst, 0o755) //nolint:errcheck
			_ = copyDirContents(src, dst)
		} else {
			copyFileIfExists(src, dst)
		}
	}
	// Interpreter: perl plus its versioned name/symlink.
	if entries, err := os.ReadDir(filepath.Join(toolsUsr, "bin")); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "perl") {
				seed(filepath.Join("bin", e.Name()))
			}
		}
	}
	// perl-base core modules under lib/<triplet>/perl-base, and any arch-indep
	// perl module dir under share/perl*.
	if libs, err := os.ReadDir(filepath.Join(toolsUsr, "lib")); err == nil {
		for _, e := range libs {
			pb := filepath.Join("lib", e.Name(), "perl-base")
			if fi, err := os.Stat(filepath.Join(toolsUsr, pb)); err == nil && fi.IsDir() {
				seed(pb)
			}
		}
	}
	if shares, err := os.ReadDir(filepath.Join(toolsUsr, "share")); err == nil {
		for _, e := range shares {
			if strings.HasPrefix(e.Name(), "perl") {
				seed(filepath.Join("share", e.Name()))
			}
		}
	}
	ushlog.Info("fs: seeded perl-base into pkgroot (/usr/bin/perl for debconf)")
}

// seedDebconfBase stages debconf's pure-perl infrastructure from the tools tree into
// the pkgroot upper (pkgUsr) BEFORE the /usr overlay mounts, so it is present and
// visible in the guest /usr for maintainer scripts: /usr/share/debconf/confmodule
// (sourced by every debconf maintainer script), /usr/share/debconf/frontend (the perl
// frontend it execs) and /usr/share/perl5/Debconf/*.pm (the modules the frontend
// loads, e.g. Debconf::Db). Installing debconf at runtime instead leaves those modules
// behind the rootless /usr overlay (a deep dir written behind the mount that the
// overlay never surfaces in-session), so `use Debconf::Db` dies "Can't locate" and the
// postinst fails. debconf is infrastructure, so it is baked into the tools tree and
// pre-seeded here, exactly like perl-base.
func (g *GuestFS) seedDebconfBase(pkgUsr string) {
	if g.ToolsDir == "" {
		return
	}
	toolsUsr := filepath.Join(g.GuestRoot, g.ToolsDir, "usr")
	if _, err := os.Stat(filepath.Join(toolsUsr, "share", "debconf", "confmodule")); err != nil {
		ushlog.Debug("fs: debconf not staged in tools, debconf maintainer scripts may fail", "toolsUsr", toolsUsr)
		return
	}
	if _, err := os.Stat(filepath.Join(pkgUsr, "share", "debconf", "confmodule")); err == nil {
		return // already seeded in a prior session (pkgroot persists)
	}
	seed := func(rel string) {
		src := filepath.Join(toolsUsr, rel)
		fi, err := os.Stat(src)
		if err != nil {
			return
		}
		dst := filepath.Join(pkgUsr, rel)
		if fi.IsDir() {
			os.MkdirAll(dst, 0o755) //nolint:errcheck
			_ = copyDirContents(src, dst)
		} else {
			copyFileIfExists(src, dst)
		}
	}
	seed(filepath.Join("share", "debconf"))          // confmodule, frontend, confmodule.sh, templates
	seed(filepath.Join("share", "perl5", "Debconf")) // Db.pm, Client/, DbDriver/, Element/, FrontEnd/, ...
	for _, b := range []string{"debconf", "debconf-escape", "debconf-communicate", "debconf-apt-progress"} {
		seed(filepath.Join("bin", b))
	}
	ushlog.Info("fs: seeded debconf into pkgroot (confmodule + frontend + Debconf modules for maintainer scripts)")
}

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
		ensureVarWritable(varDst)
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
	// Debian sources.list (e.g. a Debian-derivative host).
	// Always clear them: apt-get update recreates them in seconds.
	invalidateAptLists(varDst) //nolint:errcheck

	return nil
}

// ensureVarWritable gives the guest a writable /var/log, /var/cache and /var/tmp
// on the overlay path. The lower /var comes from the host rootfs, where these
// dirs can be owned by an uid the guest userns does not map (Sinty ships
// /var/log owned by "nobody"). The overlay copies them up preserving that owner,
// and the guest's uid 0 has no CAP_CHOWN/CAP_DAC_OVERRIDE over an unmapped uid,
// so a chown fails and a write gets EACCES: fontconfig.postinst writing
// /var/log/fontconfig.log was the visible failure, cascading to debconf,
// libglib2.0-0 and fontconfig-config all "Errors were encountered" and apt
// exiting 100 even though every file had unpacked. A fresh tmpfs mounted here is
// owned by the guest uid 0 and writable; these dirs hold only regenerable
// session state (logs, caches, temp), so nothing is lost by shadowing the lower.
// The tmpfs fallback path already creates a fresh /var, so it needs no fixup.
func ensureVarWritable(varDst string) {
	for _, d := range []string{"log", "cache", "tmp"} {
		p := filepath.Join(varDst, d)
		if err := os.MkdirAll(p, 0o755); err != nil {
			ushlog.Debug("fs: ensure /var dir", "dir", d, "err", err)
			continue
		}
		mode := "mode=0755"
		if d == "tmp" {
			mode = "mode=1777" // world-writable, like /tmp
		}
		if err := unix.Mount("tmpfs", p, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, mode); err != nil {
			ushlog.Debug("fs: tmpfs over /var/"+d+" failed", "err", err)
		}
	}
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
	// The bind target must exist. When /var came in as an overlay the host's home
	// path is already present, but on a tmpfs+bind /var (overlay unavailable) it is
	// not, so create it unconditionally.
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("fs: guest home mountpoint: %w", err)
	}
	if err := bindMount(guestHome, dst, false); err != nil {
		return fmt.Errorf("fs: bind guest home: %w", err)
	}

	// 2. Expose the real home DATA dirs, write-isolated by default: the guest
	//    READS the host directory but every
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
	// Create the pkgroot up front (even on a brand-new profile with nothing
	// installed). It must exist so bindPkgLayer can bind it into the guest and
	// setupUsr can overlay it onto /usr BEFORE the first `pkg install`: dpkg unpacks
	// with instdir pointing here, and its maintainer scripts read those files back
	// through the /usr overlay. Without pre-creating it the overlay was skipped and
	// the first install always failed (debconf confmodule not found).
	if err := os.MkdirAll(filepath.Join(src, "usr"), 0o755); err != nil {
		ushlog.Debug("fs: pkgroot pre-create failed", "src", src, "err", err)
		return nil
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

// setupDevpts mounts a private devpts instance for the guest (required by
// dpkg/posix_openpt) and points /dev/ptmx at it. On failure it falls back to
// binding the host /dev/pts and /dev/ptmx.
func (g *GuestFS) setupDevpts() {
	devPtsDst := filepath.Join(g.GuestRoot, "dev/pts")
	ptmxDst := filepath.Join(g.GuestRoot, "dev/ptmx")

	// Try without the gid option first (user namespaces may reject gid=5).
	for _, opts := range []string{"newinstance,ptmxmode=0666,mode=620", "newinstance,ptmxmode=0666"} {
		if err := unix.Mount("devpts", devPtsDst, "devpts",
			unix.MS_NOSUID|unix.MS_NOEXEC, opts); err == nil {
			os.Remove(ptmxDst)
			os.Symlink("pts/ptmx", ptmxDst)
			return
		}
	}

	ushlog.Warn("fs: devpts mount failed, falling back to bind")
	if _, err := os.Stat("/dev/pts"); err == nil {
		if berr := bindMount("/dev/pts", devPtsDst, false); berr != nil {
			ushlog.Warn("fs: /dev/pts bind failed", "err", berr)
		}
	}
	if _, err := os.Stat("/dev/ptmx"); err == nil {
		touch(ptmxDst)
		if berr := bindMount("/dev/ptmx", ptmxDst, false); berr != nil {
			ushlog.Warn("fs: /dev/ptmx bind failed", "err", berr)
		}
	}
}

// setupDevShm mounts a tmpfs at the guest /dev/shm.
func (g *GuestFS) setupDevShm() {
	shmDir := filepath.Join(g.GuestRoot, "dev/shm")
	os.MkdirAll(shmDir, 01777)
	unix.Mount("tmpfs", shmDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777")
}

// bindXDGRuntime mounts XDG_RUNTIME_DIR in the guest.
// bindXDGRuntime gives the guest a FRESH runtime dir (a directory on its own
// /run tmpfs), NOT a bind of the host XDG_RUNTIME_DIR.
//
// SECURITY: binding the whole host runtime dir used to expose `bus`, the host
// session bus. That bus carries org.freedesktop.systemd1, so a guest could call
// StartTransientUnit and have the host `systemd --user` spawn a process OUTSIDE
// every namespace as the host user, bypassing all of ush's containment. We now
// expose ONLY the specific channels the guest legitimately needs: the ush
// sockets subdir (broker + seccomp-notify) and individual GUI/audio sockets.
// The host session bus is never visible inside the guest.
func (g *GuestFS) bindXDGRuntime() error {
	if g.XDGRuntimeDir == "" {
		return nil
	}
	if _, err := os.Stat(g.XDGRuntimeDir); err != nil {
		ushlog.Warn("fs: XDG_RUNTIME_DIR not available on host, skipping", "path", g.XDGRuntimeDir)
		return nil
	}

	guestRT := filepath.Join(g.GuestRoot, g.XDGRuntimeDir)
	if err := os.MkdirAll(guestRT, 0700); err != nil {
		return fmt.Errorf("fs: mkdir guest XDG_RUNTIME_DIR: %w", err)
	}

	// 1) The ush sockets directory (broker control socket + seccomp-notify fd
	//    socket). This is the ONLY ush channel the guest needs; the host bus
	//    stays out entirely.
	ushHost := filepath.Join(g.XDGRuntimeDir, "ush")
	if err := os.MkdirAll(ushHost, 0700); err != nil {
		return fmt.Errorf("fs: mkdir host ush runtime dir: %w", err)
	}
	ushGuest := filepath.Join(guestRT, "ush")
	if err := os.MkdirAll(ushGuest, 0700); err != nil {
		return fmt.Errorf("fs: mkdir guest ush runtime dir: %w", err)
	}
	if err := bindMount(ushHost, ushGuest, false); err != nil {
		return fmt.Errorf("fs: bind ush runtime dir: %w", err)
	}

	// 2) Specific desktop sockets, exposed one by one (never the session bus).
	//    Wayland and PipeWire are sockets; PulseAudio's is a directory.
	for _, name := range []string{"wayland-0", "wayland-1", "pipewire-0", "pulse"} {
		src := filepath.Join(g.XDGRuntimeDir, name)
		fi, err := os.Stat(src)
		if err != nil {
			continue
		}
		dst := filepath.Join(guestRT, name)
		if fi.IsDir() {
			if err := os.MkdirAll(dst, 0700); err != nil {
				continue
			}
		} else {
			// A bind mount needs an existing target; a placeholder file is fine,
			// the bind replaces it with the real socket inode.
			if f, err := os.OpenFile(dst, os.O_CREATE, 0600); err == nil {
				f.Close()
			} else {
				continue
			}
		}
		if err := bindMount(src, dst, false); err != nil {
			ushlog.Warn("fs: bind desktop socket failed, skipping", "socket", name, "err", err)
		}
	}

	ushlog.Info("fs: guest runtime dir isolated (host session bus NOT exposed)",
		"runtime", g.XDGRuntimeDir)
	return nil
}

// blockPackageManagers overwrites apt/dpkg binaries with blocking wrappers in the
// /usr/bin overlay layer. The real binaries are copied to LayerDir/ush-exec (writable,
// outside the guest rootfs bind-only) and then bind-mounted to /run/ush/exec in the guest.
// The internal pkg manager uses /run/ush/exec/apt-get to bypass the block.
// Also compiles the chown LD_PRELOAD shim that makes chown/lchown/fchown/fchownat
// return 0 on EPERM/EINVAL (unmapped GIDs in user namespace), preventing dpkg aborts.
func (g *GuestFS) blockPackageManagers() error {
	blockedBins := []string{
		"apt", "apt-get", "apt-cache", "apt-mark",
		"dpkg", "dpkg-reconfigure",
	}

	// 1. Build ush-exec: directory with real binaries used by the runtime.
	//    Cascade search: ToolsDir > /usr/local/bin > /usr/bin.
	ushExecHost := filepath.Join(g.LayerDir, "ush-exec")
	if err := os.MkdirAll(ushExecHost, 0755); err != nil {
		ushlog.Warn("fs: unable to create ush-exec dir", "path", ushExecHost, "err", err)
	} else {
		searchPaths := []string{"/usr/local/bin", "/usr/bin", "/bin"}
		if g.ToolsDir != "" {
			// ToolsDir has FHS structure extracted from .debs (usr/bin, bin).
			searchPaths = append([]string{
				filepath.Join(g.ToolsDir, "usr", "bin"),
				filepath.Join(g.ToolsDir, "bin"),
			}, searchPaths...)
		}
		// dpkg's unpack/query helpers are not blocked, but dpkg execs them by name,
		// so they must be staged alongside it in the guest-visible /run/ush/exec
		// (Dpkg::Path points here). Without dpkg-deb, apt install cannot unpack.
		stageBins := append([]string{}, blockedBins...)
		// dpkg helpers + maintainer-script tools (preinst/postinst call these by
		// name via PATH) + GNU tar for dpkg-deb's unpack.
		stageBins = append(stageBins,
			"dpkg-deb", "dpkg-split", "dpkg-query", "dpkg-trigger",
			"dpkg-divert", "update-alternatives", "dpkg-maintscript-helper", "tar",
			"gpgv", "apt-key") // signature verification of the apt release files
		for _, bin := range stageBins {
			for _, dir := range searchPaths {
				src := filepath.Join(dir, bin)
				if data, err := os.ReadFile(src); err == nil {
					dst := filepath.Join(ushExecHost, bin)
					if werr := os.WriteFile(dst, data, 0755); werr != nil {
						ushlog.Warn("fs: unable to copy binary", "bin", bin, "err", werr)
					} else {
						ushlog.Debug("fs: binary copied", "bin", bin, "src", src)
					}
					break
				}
			}
		}

		// If ToolsDir contains libs (needed for dynamic apt), stage them into
		// ush-exec/lib so ld.so finds them at the guest-visible /run/ush/exec/lib.
		// Copy EVERY lib dir, not just the first: the apt-get binary links against
		// libapt-private.so.0.0 which lives only in usr/lib/x86_64-linux-gnu, while
		// the earlier-matching usr/lib holds just the apt/dpkg method dirs. Breaking
		// on the first match left libapt-private out and apt-get died with
		// "error while loading shared libraries: libapt-private.so.0.0".
		if g.ToolsDir != "" {
			dst := filepath.Join(ushExecHost, "lib")
			os.MkdirAll(dst, 0755)
			for _, libDir := range []string{"usr/lib", "usr/lib/x86_64-linux-gnu", "lib", "lib/x86_64-linux-gnu"} {
				src := filepath.Join(g.ToolsDir, libDir)
				if fi, err := os.Stat(src); err == nil && fi.IsDir() {
					copyDirContents(src, dst) //nolint:errcheck
				}
			}

			// Stage dpkg's data tables (cputable/tupletable/abitable/ostable) so the
			// bootstrapped dpkg can print the architecture. Without them apt fails
			// with "Error reading the CPU table" / "Unable to determine a suitable
			// packaging system type" on a non-Debian guest that has no /usr/share/dpkg.
			// DPKG_DATADIR is pointed at /run/ush/exec/share/dpkg by the pkg manager.
			if fi, err := os.Stat(filepath.Join(g.ToolsDir, "usr", "share", "dpkg")); err == nil && fi.IsDir() {
				dpkgData := filepath.Join(g.ToolsDir, "usr", "share", "dpkg")
				ddst := filepath.Join(ushExecHost, "share", "dpkg")
				os.MkdirAll(ddst, 0755)
				copyDirContents(dpkgData, ddst) //nolint:errcheck
				// Also place them at the compiled-in default /usr/share/dpkg inside
				// the guest: apt runs dpkg with a sanitized environment, so the
				// DPKG_DATADIR override is not always honored and dpkg falls back to
				// this path when reading the CPU/tuple tables.
				guestDpkgData := filepath.Join(g.GuestRoot, "usr", "share", "dpkg")
				if err := os.MkdirAll(guestDpkgData, 0755); err == nil {
					copyDirContents(dpkgData, guestDpkgData) //nolint:errcheck
				} else {
					ushlog.Warn("fs: unable to stage dpkg data at guest /usr/share/dpkg", "err", err)
				}
			}

			// Stage apt's method drivers (http/gpgv/...) into a guest-visible path.
			// The toolsDir is not reachable from inside the namespace, so apt
			// otherwise reports "The method driver /usr/lib/apt/methods/http could
			// not be found". The pkg manager points Dir::Bin::Methods here.
			if fi, err := os.Stat(filepath.Join(g.ToolsDir, "usr", "lib", "apt", "methods")); err == nil && fi.IsDir() {
				mdst := filepath.Join(ushExecHost, "apt-methods")
				os.MkdirAll(mdst, 0755)
				copyDirContents(filepath.Join(g.ToolsDir, "usr", "lib", "apt", "methods"), mdst) //nolint:errcheck
			}

			// Sinty ships no ldconfig (it uses a prebuilt ld.so.cache), but dpkg
			// aborts configure with "expected program not found" when ldconfig is
			// missing from PATH. ush resolves guest libraries via pkgroot binds and
			// LD_LIBRARY_PATH, not the global cache, so a no-op ldconfig is correct
			// here; stage it in the guest-visible exec dir (added to dpkg's PATH).
			ldstub := filepath.Join(ushExecHost, "ldconfig")
			if err := os.WriteFile(ldstub, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
				ushlog.Warn("fs: unable to stage ldconfig stub", "err", err)
			}

			// Stage the Debian archive keyring so apt can verify InRelease with the
			// staged gpgv; the guest sources.list references it via [signed-by=...].
			if g.ToolsDir != "" {
				keySrc := filepath.Join(g.ToolsDir, "usr", "share", "keyrings", "debian-archive-keyring.gpg")
				if data, err := os.ReadFile(keySrc); err == nil {
					kdst := filepath.Join(ushExecHost, "keyrings")
					os.MkdirAll(kdst, 0755)
					if werr := os.WriteFile(filepath.Join(kdst, "debian-archive-keyring.gpg"), data, 0644); werr != nil {
						ushlog.Warn("fs: unable to stage debian archive keyring", "err", werr)
					}
				} else {
					ushlog.Warn("fs: debian archive keyring not found in tools", "err", err)
				}
			}
		}

	}

	// 2. Install the LD_PRELOAD shim into the host-side layer BEFORE the bind,
	// so that everything the guest needs is already in place and the bind can be
	// mounted read-only. Also intercepts getuid/getgid family for Electron apps.
	shimDst := filepath.Join(ushExecHost, "ush-chown-shim.so")
	if err := installPreloadShim(shimDst); err != nil {
		return fmt.Errorf("fs: install preload shim: %w", err)
	}

	// 3. Bind-mount LayerDir/ush-exec -> $GUESTROOT/run/ush/exec, READ-ONLY.
	// The guest only ever reads/execs these files (real apt/dpkg + the shim);
	// it has no legitimate reason to write here. A RW bind would let a guest
	// trojan the shim or the apt/dpkg helpers, which are re-loaded/re-executed
	// by later guest sessions (and would become a host-code-execution vector
	// the moment any host helper ran from this layer). Fail closed: keep RO.
	ushExecGuest := filepath.Join(g.GuestRoot, "run", "ush", "exec")
	if err := os.MkdirAll(ushExecGuest, 0755); err != nil {
		ushlog.Warn("fs: unable to create ush-exec guest dir", "err", err)
	} else if err := bindMount(ushExecHost, ushExecGuest, true); err != nil {
		ushlog.Warn("fs: bind ush-exec failed", "src", ushExecHost, "dst", ushExecGuest, "err", err)
	} else {
		ushlog.Debug("fs: ush-exec bind ok (ro)", "dst", ushExecGuest)
	}

	// 4. /usr stays RO throughout the guest. Blocking wrappers are handled
	// by the shell (execHandler). The real apt/dpkg binaries are in /run/ush/exec/
	// for internal use by the pkg manager.

	return nil
}

func installPreloadShim(dst string) error {
	ushlog.Info("fs: installing shim", "dst", dst)

	if err := compilePreloadShim(dst); err == nil {
		ushlog.Info("fs: shim compiled", "path", dst)
		return nil
	} else {
		// Not being able to compile is expected before the user installs a C compiler; the
		// prebuilt fallback below covers it. Log at INFO, not WARN, so the normal pre-gcc dsh
		// start is not alarming. A genuine failure still surfaces as an error if the fallback
		// is also missing.
		ushlog.Info("fs: shim not compiled (no cc yet), using prebuilt fallback", "err", err)
	}

	for _, src := range preloadShimFallbacks() {
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if err := os.WriteFile(dst, data, 0755); err != nil {
			return fmt.Errorf("copy prebuilt shim from %s: %w", src, err)
		}
		ushlog.Info("fs: shim copied from prebuilt fallback", "src", src, "dst", dst)
		return nil
	}

	return fmt.Errorf("no C compiler available and no prebuilt shim found")
}

func compilePreloadShim(dst string) error {
	cc, err := exec.LookPath("cc")
	if err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp("", "dpkg_shim_*.c")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(preload.DpkgShimC)); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	cmd := exec.Command(cc, "-shared", "-fPIC", "-o", dst, tmpFile.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", cmd.String(), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func preloadShimFallbacks() []string {
	candidates := []string{
		filepath.Join("preload", "ush-chown-shim.so"),
		filepath.Join("/usr", "lib", "ush", "ush-chown-shim.so"),
		filepath.Join("/usr", "local", "lib", "ush", "ush-chown-shim.so"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "preload", "ush-chown-shim.so"),
			filepath.Join(exeDir, "..", "lib", "ush", "ush-chown-shim.so"),
		)
	}
	return candidates
}

// pivotRoot performs pivot_root to make GuestRoot the new /.
func (g *GuestFS) pivotRoot() error {
	newRoot := g.GuestRoot
	putOld := filepath.Join(newRoot, "old_root")

	// The mount point must be a real mount point.
	if err := unix.Mount(newRoot, newRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("fs: bind self for pivot_root: %w", err)
	}

	if err := syscall.PivotRoot(newRoot, putOld); err != nil {
		return fmt.Errorf("fs: pivot_root: %w", err)
	}

	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("fs: chdir / after pivot_root: %w", err)
	}

	// Unmount the old root.
	if err := unix.Unmount("/old_root", unix.MNT_DETACH); err != nil {
		ushlog.Warn("fs: unable to unmount old_root", "err", err)
	}

	os.Remove("/old_root")

	ushlog.Debug("fs: pivot_root complete")
	return nil
}

// Teardown unmounts everything in an orderly fashion.
func (g *GuestFS) Teardown() error {
	ushlog.Info("fs: teardown guest rootfs")
	// Mounts are automatically unmounted when the namespace dies.
	// Only remove the guest root temporary directory.
	return os.RemoveAll(g.GuestRoot)
}

// bindMount performs a bind mount (RO or RW).
// The remount RO is best-effort: in user namespace some mounts propagated
// from the host cannot be remounted RO.
func bindMount(src, dst string, ro bool) error {
	flags := uintptr(unix.MS_BIND | unix.MS_REC)
	if err := unix.Mount(src, dst, "", flags, ""); err != nil {
		return fmt.Errorf("bind %s->%s: %w", src, dst, err)
	}
	if ro {
		flags = unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_REC
		if err := unix.Mount(src, dst, "", flags, ""); err != nil {
			// Non-fatal: the kernel enforces its own policies anyway.
			ushlog.Warn("fs: remount RO failed (best-effort)", "dst", dst, "err", err)
		}
	}
	return nil
}
