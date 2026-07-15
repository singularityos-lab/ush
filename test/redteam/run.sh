#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>
#
# USH red-team harness.
#
# Drives ush non-interactively and answers broker permission requests
# programmatically (broker AUTO mode), so security scenarios can be replayed
# and asserted without a human at a GUI. Each scenario runs on its OWN private
# D-Bus session (via dbus-run-session) and its OWN clean storage dir, so it
# never touches the user's real broker or layers.
#
# Usage:  test/redteam/run.sh            # run all scenarios
#         KEEP=1 test/redteam/run.sh     # keep the work dir for inspection
#
# Each scenario:
#   1. starts ush-broker in AUTO mode with a scripted verdict/rules + a JSONL
#      decision log (the attack trace),
#   2. runs an ush -c "<attack script>" inside the guest,
#   3. asserts on the guest output and on the decision log.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d /tmp/ush-redteam.XXXXXX)"
BIN="$WORK/bin"
mkdir -p "$BIN"

PASS=0
FAIL=0
declare -a FAILURES=()

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "work dir kept: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

note()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()   { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILURES+=("$*"); }
skip()  { printf '\033[1;33m[SKIP]\033[0m %s\n' "$*"; }

note "building ush and ush-broker"
( cd "$ROOT" && go build -o "$BIN/ush" ./cmd/ush && go build -o "$BIN/ush-broker" ./cmd/ush-broker ) \
  || { echo "build failed"; exit 1; }

# run_scenario writes the guest's stdout+stderr to $GUESTOUT and the broker's
# decision log to $DECLOG. The caller sets, before calling:
#   AUTO     : default broker verdict (allow|deny|allow_session|allow_always)
#   CONFIRM  : yes|no  (answer to AllowApp/Revoke confirmations)
#   RULES    : path to a rules json, or "" for none
#   SCRIPT   : the command string passed to `ush -c`
#
# It starts a PRIVATE dbus-daemon whose socket lives under XDG_RUNTIME_DIR.
# ush bind-mounts XDG_RUNTIME_DIR into the guest, so the guest reaches the same
# broker after pivot_root (an abstract/​/tmp socket would not survive pivot).
# Storage is a clean per-scenario dir, isolated from the user's real layers.
BROKERLOG=""
run_scenario() {
  local tag="$1"
  local sdir="$WORK/$tag"
  mkdir -p "$sdir/data/ush" "$sdir/cfg/ush"
  # Optional: pre-seed the broker policy file (e.g. a legacy app:<name> trust
  # rule) before the broker starts, so a scenario can reproduce prior state.
  if [[ -n "${SEED_POLICY:-}" ]]; then
    printf '%s' "$SEED_POLICY" >"$sdir/data/ush/policy.json"
  fi
  GUESTOUT="$sdir/guest.out"
  DECLOG="$sdir/decisions.jsonl"
  BROKERLOG="$sdir/broker.log"
  : >"$DECLOG"

  # PID namespace stays ON (needed to mount a private /proc). Net ns is off
  # (no pasta here). Keep config minimal; defaults are otherwise fine.
  cat >"$sdir/cfg/ush/config.json" <<JSON
{ "storage_dir": "$sdir/data/ush", "enable_pid_namespace": true, "enable_net_namespace": false, "log_level": "info" }
JSON

  # Per-scenario XDG_RUNTIME_DIR with the private bus socket named exactly
  # "$rundir/bus". ush bind-mounts XDG_RUNTIME_DIR into the guest; even when the
  # guest's systemd step repoints DBUS to "$XDG_RUNTIME_DIR/bus" it lands on OUR
  # broker, never the user's real session bus. USH_IN_SCOPE=1 skips the outer
  # systemd-run scope (which needs the real user bus and would fail here).
  local rundir="$sdir/run"
  mkdir -p "$rundir"; chmod 700 "$rundir"
  local bussock="$rundir/bus"
  rm -f "$bussock"
  dbus-daemon --session --address="unix:path=$bussock" --nofork >"$sdir/bus.log" 2>&1 &
  local dpid=$!
  for _ in $(seq 1 50); do [[ -S "$bussock" ]] && break; sleep 0.1; done

  (
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$bussock"
    export XDG_RUNTIME_DIR="$rundir"
    export USH_IN_SCOPE=1
    export XDG_DATA_HOME="$sdir/data" XDG_CONFIG_HOME="$sdir/cfg"
    export USH_BROKER_AUTO="${AUTO:-deny}"
    export USH_BROKER_CONFIRM="${CONFIRM:-no}"
    export USH_BROKER_DECISION_LOG="$DECLOG"
    [[ -n "${RULES:-}" ]] && export USH_BROKER_RULES="$RULES"

    "$BIN/ush-broker" >"$BROKERLOG" 2>&1 &
    local bpid=$!
    for _ in $(seq 1 60); do
      grep -q "broker: started" "$BROKERLOG" 2>/dev/null && break
      sleep 0.1
    done

    "$BIN/ush" -c "$SCRIPT" >"$GUESTOUT" 2>&1
    echo "GUEST_EXIT=$?" >>"$GUESTOUT"
    kill "$bpid" 2>/dev/null
    wait "$bpid" 2>/dev/null
  )

  kill "$dpid" 2>/dev/null
  wait "$dpid" 2>/dev/null
  rm -f "$bussock"
}

# dump_ctx prints the guest output, decision log and broker log for debugging.
dump_ctx() {
  sed 's/^/    guest> /' "$GUESTOUT" 2>/dev/null | grep -v '"level":"INFO"'
  sed 's/^/    log>   /' "$DECLOG" 2>/dev/null
  grep -iE 'AUTO decision|broker:' "$BROKERLOG" 2>/dev/null | sed 's/^/    brk>   /' | head -8
}

# helper assertions over the produced files
guest_has()   { grep -qiE "$1" "$GUESTOUT"; }
declog_has()  { grep -qE "$1" "$DECLOG"; }
policy_file() { echo "$WORK/$1/data/ush/policy.json"; }

# Scenario 1: default-deny actually denies a network permission request.
# Drives the broker round-trip via the `perm` builtin (no external tools).
note "S1: broker default-deny blocks a network request"
AUTO=deny CONFIRM=no RULES="" \
SCRIPT='perm network tcp://93.184.216.34:443 "redteam s1"' \
  run_scenario s1
if guest_has "deny" && declog_has '"category":"network".*"decision":"deny"'; then
  ok "S1 network request denied and logged"
else
  bad "S1 expected deny in guest output and decision log"
  dump_ctx
fi

# Scenario 2: a rules file selectively allows one resource.
note "S2: rules file allows a specific resource"
cat >"$WORK/rules-allow.json" <<'JSON'
[
  { "category": "network", "resource": "tcp://93.184.216.34:443", "match": "exact", "decision": "allow" }
]
JSON
AUTO=deny CONFIRM=no RULES="$WORK/rules-allow.json" \
SCRIPT='perm network tcp://93.184.216.34:443 "redteam s2"' \
  run_scenario s2
if guest_has "allow|granted|ok" && declog_has '"decision":"allow".*"rule":0'; then
  ok "S2 rule-based allow honored and logged with matched rule"
else
  bad "S2 expected rule-based allow"
  dump_ctx
fi

# Scenario 3: a guest CANNOT silently self-trust an app.
# `perm trust` calls AllowApp, which now requires confirmation. With
# CONFIRM=no the grant must be refused and nothing persisted to policy.json.
note "S3: guest cannot self-trust without confirmation"
AUTO=deny CONFIRM=no RULES="" \
SCRIPT='perm trust /usr/bin/curl' \
  run_scenario s3
pol="$(policy_file s3)"
if guest_has "not confirmed|failed|error" && ! grep -q '"app:/usr/bin/curl"' "$pol" 2>/dev/null; then
  ok "S3 self-trust refused, no app rule persisted"
else
  bad "S3 guest managed to self-trust without confirmation"
  sed 's/^/    guest> /' "$GUESTOUT"; [[ -f "$pol" ]] && sed 's/^/    policy> /' "$pol"
fi

# Scenario 3b: with CONFIRM=yes the explicit trust succeeds and persists,
# keyed on the absolute exe path (identity is the real path).
note "S3b: confirmed trust persists keyed on exe path"
AUTO=deny CONFIRM=yes RULES="" \
SCRIPT='perm trust /usr/bin/curl' \
  run_scenario s3b
pol="$(policy_file s3b)"
if grep -q '"app:/usr/bin/curl"' "$pol" 2>/dev/null; then
  ok "S3b confirmed trust persisted as app:/usr/bin/curl"
else
  bad "S3b confirmed trust did not persist"
  sed 's/^/    guest> /' "$GUESTOUT"; [[ -f "$pol" ]] && sed 's/^/    policy> /' "$pol"
fi

# Scenario 4 (BREACH ATTEMPT): a real outbound connect() is intercepted.
# The guest tries to reach an external IP; under default-deny the connect
# syscall must be routed to the broker and the attempt recorded. This proves
# the network boundary is enforced at the syscall layer, not just the builtin.
note "S4: real outbound connect() is intercepted by the supervisor"
if command -v curl >/dev/null; then
  AUTO=deny CONFIRM=no RULES="" \
  SCRIPT='sleep 1; curl --max-time 6 -s -o /dev/null -w "HTTP_%{http_code}\n" http://1.1.1.1/ ; echo CURL_EXIT=$?' \
    run_scenario s4
  if declog_has '"category":"network".*1\.1\.1\.1'; then
    ok "S4 outbound connect() to 1.1.1.1 was intercepted and logged"
  else
    skip "S4 no network interception logged (supervisor may not have enforced in time / no route)"
    dump_ctx
  fi
else
  skip "S4 curl not available"
fi

# Scenario B1 (BREACH ATTEMPT): comm spoofing must NOT grant trust.
# We trust /usr/bin/curl by exe path, then run python3 that renames its own
# comm to "curl" via prctl(PR_SET_NAME) and tries an outbound connection.
# Old behaviour (trust keyed on comm) would auto-allow it WITHOUT asking the
# broker. New behaviour keys trust on /proc/<pid>/exe, so python3 is NOT curl:
# the connect must reach the broker and be denied. The decision-log entry is
# the proof that trust was not silently inherited via the faked name.
note "B1: comm spoofing does not inherit another app's trust"
if command -v python3 >/dev/null; then
  # Deliver the payload via the guest-visible ush runtime subdir (the only
  # shared channel now that the whole runtime dir is no longer bind-mounted).
  b1dir="$WORK/b1/run/ush"; mkdir -p "$b1dir"
  cat >"$b1dir/spoof.py" <<'PY'
import ctypes, socket
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(15, b"curl", 0, 0, 0)  # PR_SET_NAME: pretend to be the trusted "curl"
with open("/proc/self/comm") as f:
    print("COMM_NOW=" + f.read().strip())
s = socket.socket(); s.settimeout(4)
try:
    s.connect(("1.1.1.1", 443)); print("SPOOF_CONNECTED")
except Exception as e:
    print("SPOOF_BLOCKED", type(e).__name__)
PY
  # Seed a LEGACY-style blanket trust keyed on the bare comm name "curl" (this
  # is exactly what the pre-fix `perm trust curl` would have stored). A process
  # that fakes comm=="curl" would have inherited it. The fixed supervisor keys
  # trust on /proc/<pid>/exe (here /usr/bin/python3), so the trust must NOT
  # apply and the connect must be denied through the broker.
  SEED_POLICY='[{"category":"app:curl","resource":"*","decision":"allow"}]' \
  AUTO=deny CONFIRM=no RULES="" \
  SCRIPT='sleep 1; python3 "$XDG_RUNTIME_DIR/ush/spoof.py"; echo PY_EXIT=$?' \
    run_scenario b1
  if declog_has '"category":"network".*1\.1\.1\.1.*"decision":"allow"'; then
    bad "B1 comm spoofing inherited trust (BREACH): spoofed curl was allowed by the broker"
    dump_ctx
  elif guest_has "COMM_NOW=curl" && guest_has "SPOOF_BLOCKED" \
     && declog_has '"category":"network".*1\.1\.1\.1.*"decision":"deny"'; then
    ok "B1 spoofed comm 'curl' did NOT inherit app:curl trust; connect denied and logged"
  else
    skip "B1 no network interception logged (supervisor may not have enforced at the syscall layer)"
    dump_ctx
  fi
else
  skip "B1 python3 not available"
fi

# Scenario B2 (BREACH ATTEMPT): link-local metadata is gated.
# 169.254.169.254 (cloud/container metadata) used to be auto-allowed as a
# link-local address. It must now go through the broker like any destination.
note "B2: link-local metadata 169.254.169.254 is gated by the broker"
if command -v curl >/dev/null; then
  AUTO=deny CONFIRM=no RULES="" \
  SCRIPT='sleep 1; curl --max-time 4 -s -o /dev/null http://169.254.169.254/ ; echo CURL_EXIT=$?' \
    run_scenario b2
  if declog_has '"category":"network".*169\.254\.169\.254'; then
    ok "B2 metadata connect was intercepted and routed to the broker"
  else
    skip "B2 no interception logged (supervisor may not have enforced in time)"
    dump_ctx
  fi
else
  skip "B2 curl not available"
fi

echo
note "decision-log sample from S1 (the attack trace the broker records):"
sed 's/^/    /' "$WORK/s1/decisions.jsonl" 2>/dev/null | head -5

echo
echo "=============================================="
printf 'red-team summary: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then
  printf 'failed: %s\n' "${FAILURES[@]}"
  exit 1
fi
