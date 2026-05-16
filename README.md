# ush, a secure application runtime for Linux

A harder-than-ChromeOS application environment, without `sudo`, `pkexec`, or
traditional privilege elevators. Semantic-layer package management, a host-side
permission broker, and a custom shell with security builtins.

## Vision

ush is a micro user-OS layered on top of the base system:

- **Immutable host**: the host filesystem stays read-only.
- **Mutable guest**: changes live only in overlay layers.
- **No implicit privilege**: anything crossing the host/guest boundary goes
  through a broker with explicit policy.
- **Layer-based packages**: reversible, ephemeral, or persistent installs.

It ships two profiles from the same binary:

- **`ush`** (secure): the locked-down application sandbox described above.
- **`dsh`** (developer): the same shell on a profile that trades isolation for
  power, so nested rootless `podman`/`distrobox`, `/dev/fuse` and a subordinate
  id range work. It is explicitly **not** a security boundary.

## Architecture

```
Host (Debian sid / Vanilla OS)
  +- ush (no real root)
       +- user namespace   (guest uid maps to the host user)
       +- mount namespace  (overlay: host RO + layer upper)
       +- pid namespace    (isolated from host /proc)
       +- net namespace    (pasta userspace NAT, or built-in serviced egress)
       +- ipc + uts namespace
       |
       +- /etc   -> tmpfs + copy (host /etc as base)
       +- /var   -> overlayfs or tmpfs + copy (host /var as lower)
       +- /home  -> bind RW (write-isolated by default)
       +- /proc  -> isolated proc namespace
       +- /run   -> per-session tmpfs
            |
            +- systemd --user (guest)
                 +- ush shell (pkg, broker client, job control)
```

## Usage

```bash
ush                  # open an interactive shell in the guest
ush -c "command"     # run a command and return
ush -v               # verbose (info-level logs)

dsh                  # developer profile (podman/distrobox capable)
```

### Package runtime

```bash
pkg install htop            # install into the persistent layer
pkg install --one-time htop # install into an ephemeral, session-scoped layer
pkg remove htop             # remove from the layer
pkg burn htop               # destroy the package's layer files
pkg diff                    # show the delta from the base system
pkg inspect htop            # files, scripts, units, risk
pkg freeze                  # promote the ephemeral layer to persistent
pkg list                    # installed packages
pkg compat <pkg>            # report runtime compatibility
```

### Security builtins

```bash
perm trust-dir <dir>   # grant a directory full host read-write ("Share with Linux")
scan <path>            # on-demand antivirus scan (served by the singd daemon)
guard status           # Landlock + daemon posture summary
quarantine list        # manage quarantined files
restart                # re-exec the shell in place
```

### Permission broker

The broker runs on the host and arbitrates every privileged request from the
guest. It is normally started by its systemd user service (installed by
`make install`):

```bash
ush-broker             # start the host-side broker manually
```

## Install

```bash
make install     # build ush + ush-broker, link dsh, install and start the broker service
make uninstall   # remove binaries and the broker service
```

Binaries go to `~/.local/bin`; the broker unit to `~/.config/systemd/user`.

## Storage

```
~/.local/share/ush/
  layers/
    persistent/   # permanent layer
    ephemeral/    # per-session ephemeral layers
  sessions/       # active session metadata
  audit/          # broker audit log (JSONL)
  policy.json     # saved permission policies
```

## Security

Defense in depth:

1. **Landlock**: kernel-enforced read-only filesystem policy (hard boundary).
2. **seccomp BPF**: blocks dangerous syscalls in the kernel (ptrace, bpf, setns,
   kexec, the mount API).
3. **seccomp-notify supervisor**: inode-based exec allow-list plus
   network/device/mount policy mediated by the broker.
4. **Namespace isolation**: user, mount, pid, net, ipc, uts.
5. **Broker**: explicit user approval for privileged operations.

The on-demand antivirus, behavioral guard, and quarantine builtins talk to
`singd`, a separate daemon, over a private socket; ush works without it (those
builtins simply report it as unavailable).

### Testing

```bash
make test        # Go unit tests
make redteam     # adversarial end-to-end harness (replays breach scenarios)
make test-dsh    # nested-container smoke test (run from a dsh session)
```

The red-team harness (`test/redteam/`) drives ush non-interactively and answers
broker prompts in an automated mode, so containment scenarios stay reproducible.

## License

GPL-3.0-or-later. Copyright (C) 2026 Mirko Brombin.
