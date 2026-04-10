// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package ns manages the creation and configuration of Linux namespaces
// for the ush guest. Uses a "reexec" pattern to enter the user namespace:
//
//  1. The original process ("parent" phase) re-executes itself passing
//     USH_NS_INIT=1 in the env, with the required Cloneflags.
//  2. The child process ("child" phase) finds USH_NS_INIT=1 and completes
//     the guest filesystem and shell bootstrap.
package ns

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"golang.org/x/sys/unix"
)

// LookupSubID returns the first subordinate id range delegated to the user in
// an /etc/subuid- or /etc/subgid-style file, matched by username or numeric uid.
// ok is false when the user has no delegated range (nested containers then can't
// run, and dsh falls back to the single mapping).
func LookupSubID(file, username, uid string) (start, count int, ok bool) {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) != 3 {
			continue
		}
		if parts[0] != username && parts[0] != uid {
			continue
		}
		s, e1 := strconv.Atoi(parts[1])
		c, e2 := strconv.Atoi(parts[2])
		if e1 != nil || e2 != nil || c <= 0 {
			continue
		}
		return s, c, true
	}
	return 0, 0, false
}

const (
	EnvNSInit   = "USH_NS_INIT"
	EnvNSParent = "USH_NS_PARENT_PID"
	// EnvUsernsStub marks the developer (dsh) two-step userns stub. The stub is
	// the first exec after clone(CLONE_NEWUSER) and runs UNMAPPED (no caps); it
	// only waits on the sync fd until the parent has written the multi-range
	// uid/gid maps with newuidmap/newgidmap, then re-execs the real guest init.
	// At THAT second execve the process is already mapped to uid 0, so it
	// regains full capabilities. Writing the map after a normal clone+exec would
	// be too late: the exec would already have dropped caps while unmapped.
	EnvUsernsStub = "USH_USERNS_STUB"
	// usernsSyncFD is the inherited fd (ExtraFiles[0]) the stub blocks on.
	usernsSyncFD = 3
)

// Config describes the namespaces to create.
type Config struct {
	EnablePID bool
	EnableNet bool
	EnableIPC bool
	EnableUTS bool
	// EnableCgroupNS puts the guest in its own cgroup namespace so a cgroup2
	// mount shows the delegated subtree as root (needed for nested rootless
	// podman in dsh, and to mount cgroup2 inside the user namespace at all).
	EnableCgroupNS bool
	// Host UID to map to 0 in the guest.
	HostUID int
	HostGID int

	// UseSubuid selects the developer (dsh) mapping: in addition to 0->HostUID
	// it maps a whole subordinate uid/gid range into the guest, so nested
	// rootless containers (podman/distrobox) have ids to work with. The map is
	// written by newuidmap/newgidmap (which consult /etc/subuid, /etc/subgid),
	// not by the kernel-direct single mapping the secure ush profile uses.
	UseSubuid   bool
	SubUIDStart int
	SubUIDCount int
	SubGIDStart int
	SubGIDCount int
}

// IsChildProcess returns true if we are the re-initialized child process
// inside the user namespace.
func IsChildProcess() bool {
	return os.Getenv(EnvNSInit) == "1"
}

// IsUsernsStub reports whether this process is the developer userns stub.
func IsUsernsStub() bool { return os.Getenv(EnvUsernsStub) == "1" }

// RunUsernsStub is the developer two-step userns init. It runs UNMAPPED with no
// capabilities; it only blocks until the parent has written our uid/gid maps,
// then re-execs the real guest init in place. After this second execve the
// process is mapped to uid 0 and regains full capabilities. It never returns
// (it execs) unless something fails.
func RunUsernsStub() error {
	f := os.NewFile(uintptr(usernsSyncFD), "userns-sync")
	if f != nil {
		var buf [1]byte
		_, _ = f.Read(buf[:]) // block until the parent signals the map is written
		f.Close()
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, EnvUsernsStub+"=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, EnvNSInit+"=1")
	return syscall.Exec(self, os.Args, env)
}

// allAmbientCaps lists every capability number for SysProcAttr.AmbientCaps. The
// dev guest is mapped to the user's REAL (non-zero) uid, so the stub's execve
// would otherwise clear capabilities the way any non-root exec does, leaving the
// guest unable to mount. Setting these as ambient capabilities at clone time (in
// the child, which holds the full set as the user-namespace creator) makes them
// survive the execve into a non-root uid. Ambient caps persist across both the
// stub and the real-init execve.
func allAmbientCaps() []uintptr {
	caps := make([]uintptr, 0, unix.CAP_LAST_CAP+1)
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		caps = append(caps, uintptr(c))
	}
	return caps
}

// Reexec re-executes the current process with the requested namespaces.
// Returns the *exec.Cmd already started; the caller must wait for it to finish.
// Stdin/stdout/stderr file descriptors are inherited.
func Reexec(cfg *Config) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("ns: unable to find executable: %w", err)
	}

	flags := syscall.CLONE_NEWUSER |
		syscall.CLONE_NEWNS |
		syscall.CLONE_NEWIPC |
		syscall.CLONE_NEWUTS

	if cfg.EnablePID {
		flags |= syscall.CLONE_NEWPID
	}
	if cfg.EnableNet {
		flags |= syscall.CLONE_NEWNET
	}
	if cfg.EnableCgroupNS {
		flags |= 0x02000000 // CLONE_NEWCGROUP
	}

	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	baseEnv := append(os.Environ(), EnvNSParent+"="+strconv.Itoa(os.Getpid()))

	sysattr := &syscall.SysProcAttr{Cloneflags: uintptr(flags)}

	if cfg.UseSubuid {
		// Developer (dsh) mapping: clone the user namespace UNMAPPED (no
		// UidMappings), and have the child exec a stub that waits for us to write
		// the full subordinate id range with newuidmap/newgidmap before it execs
		// the real guest init. The two-step is required: writing a multi-range map
		// needs the setuid newuidmap helper (Go can only write a single self
		// mapping kernel-direct), and the map must land BEFORE the guest init's
		// exec or that exec drops capabilities while still unmapped.
		syncR, syncW, perr := os.Pipe()
		if perr != nil {
			return nil, fmt.Errorf("ns: subuid sync pipe: %w", perr)
		}
		cmd.ExtraFiles = []*os.File{syncR} // child sees it at fd 3
		cmd.Env = append(baseEnv, EnvUsernsStub+"=1")
		// Ambient caps set in the child (the userns creator, which holds the full
		// set) before its first execve. They survive both the stub execve and the
		// real-init execve into the user's non-zero uid, so the dev guest keeps the
		// privilege to mount overlays and run nested containers despite not being
		// uid 0. The Go runtime raises these between clone and execve.
		sysattr.AmbientCaps = allAmbientCaps()
		cmd.SysProcAttr = sysattr // no UidMappings: newuidmap writes them

		ushlog.Debug("ns: reexec (dev profile, subuid stub)", "flags", fmt.Sprintf("0x%x", flags))
		if err := cmd.Start(); err != nil {
			syncR.Close()
			syncW.Close()
			return nil, fmt.Errorf("ns: reexec failed: %w", err)
		}
		syncR.Close() // parent keeps only the write end

		if err := writeSubIDMaps(cmd.Process.Pid, cfg); err != nil {
			syncW.Close() // closing without a byte makes the stub read EOF and abort
			_ = cmd.Process.Kill()
			return nil, err
		}
		_, _ = syncW.Write([]byte{1}) // release the stub: it now re-execs mapped
		syncW.Close()
		return cmd, nil
	}

	// Secure ush profile: a single 0->HostUID mapping written kernel-direct by
	// Go BEFORE the child execs, so it execs already mapped (with capabilities).
	// setgroups stays denied (no privileged gid mapping is requested).
	cmd.Env = append(baseEnv, EnvNSInit+"=1")
	sysattr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: cfg.HostUID, Size: 1}}
	sysattr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: cfg.HostGID, Size: 1}}
	sysattr.GidMappingsEnableSetgroups = false
	cmd.SysProcAttr = sysattr

	ushlog.Debug("ns: reexec with namespace",
		"flags", fmt.Sprintf("0x%x", flags),
		"host_uid", cfg.HostUID,
		"host_gid", cfg.HostGID,
	)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ns: reexec failed: %w", err)
	}

	return cmd, nil
}

// writeSubIDMaps installs the guest's uid and gid maps with newuidmap/newgidmap.
// The dev guest keeps the user's REAL id (container id == host id), with every
// other id drawn from the subordinate range:
//
//	container [0, id)   -> subuids [start, start+id)
//	container id        -> host id          (the user's own id, identity)
//	container (id, end] -> subuids [start+id, start+count)
//
// This is the layout rootless podman uses for keep-id, and it matters: distrobox
// (and anything that runs usermod/chpasswd on your account) breaks if your user
// is uid 0, because uid 0 is already root inside the container. Mapping the user
// to their real id makes the dev world behave like a normal rootless host.
// Capabilities come from owning the user namespace, not from the id number, so
// the guest still mounts. newuidmap/newgidmap are setuid helpers that validate
// the range against /etc/subuid and /etc/subgid, so no privilege is needed here
// and guest setgroups() keeps working (needed by container runtimes).
func writeSubIDMaps(pid int, cfg *Config) error {
	uidArgs := append([]string{strconv.Itoa(pid)}, identityMapTriples(cfg.HostUID, cfg.SubUIDStart, cfg.SubUIDCount)...)
	if out, err := exec.Command("newuidmap", uidArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("ns: newuidmap: %w: %s", err, string(out))
	}
	gidArgs := append([]string{strconv.Itoa(pid)}, identityMapTriples(cfg.HostGID, cfg.SubGIDStart, cfg.SubGIDCount)...)
	if out, err := exec.Command("newgidmap", gidArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("ns: newgidmap: %w: %s", err, string(out))
	}
	return nil
}

// identityMapTriples builds the (containerID hostID size) triples that keep the
// user's own id identity-mapped and fill every other id from the subordinate
// range. Falls back to the legacy 0->host mapping plus subrange when the id
// can't sit inside the range (e.g. running as root, or count too small).
func identityMapTriples(id, subStart, subCount int) []string {
	if id <= 0 || id >= subCount {
		return []string{
			"0", strconv.Itoa(id), "1",
			"1", strconv.Itoa(subStart), strconv.Itoa(subCount),
		}
	}
	return []string{
		"0", strconv.Itoa(subStart), strconv.Itoa(id),
		strconv.Itoa(id), strconv.Itoa(id), "1",
		strconv.Itoa(id + 1), strconv.Itoa(subStart + id), strconv.Itoa(subCount - id),
	}
}

// SetHostname sets the hostname inside the UTS namespace.
// Must be called from the child process after reexec.
func SetHostname(hostname string) error {
	return syscall.Sethostname([]byte(hostname))
}
