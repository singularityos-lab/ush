// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package security

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// FileID identifies a file by its device and inode number.
// This is the Linux kernel's own identity for a file: if two FileIDs
// match, they refer to the same bytes on disk. It removes the inode-swap
// race for a FIXED path, but note the path itself is read from guest memory
// and the decision is delivered via seccomp-notify CONTINUE, which re-reads
// that memory (see ExecWhitelist for the residual TOCTOU caveat).
type FileID struct {
	Dev uint64 // st_dev - device number
	Ino uint64 // st_ino - inode number
}

// ExecWhitelist holds inode-based identity of approved executables.
// Entries are keyed by absolute path in the guest rootfs.
// All methods are safe for concurrent use.
//
// Security model:
//
//	The exec whitelist is an audit-grade layer inside the seccomp-notify
//	supervisor that discourages execution of arbitrary binaries. Inode
//	validation (dev+ino) closes the inode-swap race for a given path, but
//	the path string is read from guest memory and the allow decision is
//	delivered with SECCOMP_USER_NOTIF_FLAG_CONTINUE, which makes the kernel
//	re-read that memory. A multithreaded guest can therefore swap the path
//	after validation (the inherent seccomp-notify TOCTOU). Treat this as
//	best-effort, not a containment boundary.
//
//	Hard security boundaries come from:
//	 1. Landlock - enforces read-only filesystem policy at kernel level
//	 2. seccomp BPF - blocks dangerous syscalls at kernel level
//	 3. namespace isolation - guest processes cannot see/affect host
//	 4. This whitelist - prevents exec of unknown binaries in the guest
type ExecWhitelist struct {
	mu      sync.RWMutex
	entries map[string]FileID // guest path -> file identity
}

// NewExecWhitelist creates an empty whitelist.
func NewExecWhitelist() *ExecWhitelist {
	return &ExecWhitelist{entries: make(map[string]FileID)}
}

// BuildFromRoot walks root (a guest rootfs or a subdirectory), records
// the device+inode of every regular executable, and adds it to the whitelist.
//
// Paths under mutable or user-controlled directories are skipped
// (see ShouldSkipForWhitelist) so that attacker-controlled files in /home,
// /tmp, /run, etc. are not auto-approved. Also skips /run/ush/exec/ which
// contains trusted helpers that must not be directly exec-able by guests.
//
// RO bind mounts from the host (/usr, /bin, /lib, /sbin, /lib64) are the
// primary whitelist source - these are immutable inside the guest, so their
// inodes are stable.
//
// It is safe to call BuildFromRoot multiple times (additive).
func (w *ExecWhitelist) BuildFromRoot(root string) error {
	count := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		guestPath := "/" + rel

		if d.IsDir() && ShouldSkipForWhitelist(guestPath) {
			return filepath.SkipDir
		}

		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode()&0111 == 0 {
			return nil
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}

		w.mu.Lock()
		w.entries[guestPath] = FileID{Dev: stat.Dev, Ino: stat.Ino}
		w.mu.Unlock()
		count++
		return nil
	})
	if err != nil {
		return err
	}
	ushlog.Info("security: whitelist built", "root", root, "executables", count)
	return nil
}

// AddFile adds or updates a single path in the whitelist.
// hostPath is the actual path on the filesystem,
// guestPath is how the executor will see it inside the guest.
func (w *ExecWhitelist) AddFile(hostPath, guestPath string) error {
	fid, err := fileID(hostPath)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.entries[guestPath] = fid
	w.mu.Unlock()
	return nil
}

// Allow returns true if guestPath is in the whitelist and the file at
// hostPath has the same device+inode as the one recorded at build time.
//
// Inode identity defeats file replacement at a fixed path: a replaced file
// gets a different inode and the check fails. It does NOT close the
// seccomp-notify CONTINUE TOCTOU on the path string itself (see the type
// doc); callers must not treat a true result as a hard guarantee.
func (w *ExecWhitelist) Allow(hostPath, guestPath string) bool {
	w.mu.RLock()
	expected, ok := w.entries[guestPath]
	w.mu.RUnlock()
	if !ok {
		ushlog.Warn("security: exec denied (not in whitelist)", "path", guestPath)
		return false
	}

	current, err := fileID(hostPath)
	if err != nil {
		ushlog.Warn("security: exec denied (cannot stat)", "path", guestPath, "err", err)
		return false
	}

	if current != expected {
		ushlog.Warn("security: exec denied (inode mismatch)", "path", guestPath,
			"expected_dev", expected.Dev, "expected_ino", expected.Ino,
			"current_dev", current.Dev, "current_ino", current.Ino)
		return false
	}
	return true
}

// AddDir walks a directory and adds all executables to the whitelist.
// rootPrefix is the guest path prefix corresponding to dir on disk
// (e.g., dir="/data/pkgroot/usr/bin", rootPrefix="/usr/bin").
func (w *ExecWhitelist) AddDir(dir, rootPrefix string) error {
	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode()&0111 == 0 {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		guestPath := filepath.Join(rootPrefix, rel)

		w.mu.Lock()
		w.entries[guestPath] = FileID{Dev: stat.Dev, Ino: stat.Ino}
		w.mu.Unlock()
		count++
		return nil
	})
	ushlog.Debug("security: whitelist dir added", "dir", dir, "executables", count)
	return err
}

// Count returns the number of entries in the whitelist.
func (w *ExecWhitelist) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.entries)
}

// WhitelistEntry is a single exported record: the guest path and the kernel
// file identity (device+inode) ush validated for it.
type WhitelistEntry struct {
	Path string `json:"path"`
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
}

// Export returns a snapshot of all whitelist entries, sorted by path. The
// Singularity Guard daemon (singd) consumes this so it does not re-scan
// executables that ush has already validated by inode identity, the two
// layers share one source of truth instead of duplicating work.
func (w *ExecWhitelist) Export() []WhitelistEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]WhitelistEntry, 0, len(w.entries))
	for p, id := range w.entries {
		out = append(out, WhitelistEntry{Path: p, Dev: id.Dev, Ino: id.Ino})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// fileID returns the FileID (dev+ino) for a path.
func fileID(path string) (FileID, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return FileID{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return FileID{Dev: stat.Dev, Ino: stat.Ino}, nil
}
