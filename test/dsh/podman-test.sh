#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# dsh nested-container smoke test. Run it INSIDE a dsh session on the real host:
#
#     dsh                       # (confirm the dialog, or launch dsh directly)
#     bash test/dsh/podman-test.sh
#
# It checks, step by step, that the developer profile gives rootless podman the
# ids/syscalls/devices it needs. Each step prints PASS/FAIL so you can see
# exactly where (if anywhere) it breaks, to drive the "unblock one syscall at a
# time" tuning.
set -u

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '  ---- %s\n' "$1"; }

echo "== dsh nested-container smoke test =="

echo "[1] identity / subuid range inside the guest"
info "uid=$(id -u) gid=$(id -g)"
if [ -r /proc/self/uid_map ]; then
  info "uid_map:"; sed 's/^/        /' /proc/self/uid_map
  if [ "$(wc -l < /proc/self/uid_map)" -ge 2 ]; then pass "subuid range mapped"; else fail "only a single uid mapped (no subuid range)"; fi
fi

echo "[2] required tooling present"
for b in newuidmap newgidmap podman; do
  if command -v "$b" >/dev/null 2>&1; then pass "$b: $(command -v $b)"; else fail "$b not found in PATH"; fi
done

echo "[3] /dev/fuse + cgroup"
[ -e /dev/fuse ] && pass "/dev/fuse present" || fail "/dev/fuse missing"
[ -f /sys/fs/cgroup/cgroup.controllers ] && pass "cgroup v2 unified" || info "no unified cgroup v2 visible"

echo "[4] setns / mount-API not hard-blocked (dev seccomp)"
# unshare uses CLONE_* + mount; a quick proxy for the relaxed filter.
if unshare --user --mount true 2>/dev/null; then pass "nested user+mount namespace allowed"; else fail "nested unshare blocked (seccomp too strict?)"; fi

echo "[5] podman info"
if podman info >/tmp/dsh-podman-info.txt 2>/tmp/dsh-podman-err.txt; then
  pass "podman info ok"
  grep -E "graphDriverName|rootless|cgroupVersion" /tmp/dsh-podman-info.txt | sed 's/^/        /'
else
  fail "podman info failed:"; sed 's/^/        /' /tmp/dsh-podman-err.txt
fi

echo "[6] podman run hello-world"
if podman run --rm hello-world >/tmp/dsh-hello.txt 2>&1; then
  pass "container ran"
else
  fail "container failed:"; tail -n 8 /tmp/dsh-hello.txt | sed 's/^/        /'
fi

echo "[7] distrobox (optional)"
if command -v distrobox >/dev/null 2>&1; then
  if distrobox create --yes --name dsh-smoke --image docker.io/library/alpine:latest >/tmp/dsh-dbox.txt 2>&1 \
     && distrobox enter dsh-smoke -- echo ok >/tmp/dsh-dbox-enter.txt 2>&1; then
    pass "distrobox create+enter ok"; distrobox rm --force dsh-smoke >/dev/null 2>&1 || true
  else
    fail "distrobox failed:"; tail -n 8 /tmp/dsh-dbox.txt /tmp/dsh-dbox-enter.txt 2>/dev/null | sed 's/^/        /'
  fi
else
  info "distrobox not installed, skipping"
fi

echo "== done =="
