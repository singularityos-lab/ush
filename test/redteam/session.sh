#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>
#
# Persistent interactive USH guest, driveable one command at a time.
#
# Keeps ONE long-lived guest alive (same namespaces, same overlay, same shell
# state) and feeds it commands over a FIFO placed under XDG_RUNTIME_DIR, which
# ush bind-mounts into the guest. Shell variables, files and processes created
# by one command are visible to the next: enough to stage and then fire a
# multi-step exploit attempt.
#
# A private broker runs in AUTO mode (default verdict: deny) so the sandbox is
# at full strength and every permission request the guest makes is recorded.
#
# Usage:
#   test/redteam/session.sh start          # boot a clean guest
#   test/redteam/session.sh run 'CMD'      # run CMD inside the live guest
#   test/redteam/session.sh decisions      # show the broker decision log
#   test/redteam/session.sh stop           # tear everything down
#
# Env:
#   USH_SESSION_VERDICT=allow|deny   default broker verdict (default: deny)

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="${USH_SESSION_DIR:-/tmp/ush-session}"
BIN="$STATE/bin"
RUNDIR="$STATE/run"          # becomes the guest XDG_RUNTIME_DIR (bind-mounted)
FIFO="$RUNDIR/cmd.fifo"
OUT="$RUNDIR/out"
RC="$RUNDIR/rc"
DONE="$RUNDIR/done"
DECLOG="$STATE/decisions.jsonl"

cmd="${1:-}"

case "$cmd" in
start)
  rm -rf "$STATE"
  mkdir -p "$BIN" "$RUNDIR" "$STATE/data" "$STATE/cfg/ush"
  chmod 700 "$RUNDIR"

  ( cd "$ROOT" && go build -o "$BIN/ush" ./cmd/ush && go build -o "$BIN/ush-broker" ./cmd/ush-broker ) \
    || { echo "build failed"; exit 1; }

  cat >"$STATE/cfg/ush/config.json" <<JSON
{ "storage_dir": "$STATE/data/ush", "enable_pid_namespace": true, "enable_net_namespace": false, "log_level": "warn" }
JSON

  mkfifo "$FIFO"
  : >"$OUT"; : >"$RC"

  # Private bus + broker (AUTO deny) on a socket the guest can reach.
  local_bus="$RUNDIR/bus"
  rm -f "$local_bus"
  dbus-daemon --session --address="unix:path=$local_bus" --nofork >"$STATE/bus.log" 2>&1 &
  echo $! >"$STATE/dbus.pid"
  for _ in $(seq 1 50); do [[ -S "$local_bus" ]] && break; sleep 0.1; done

  export DBUS_SESSION_BUS_ADDRESS="unix:path=$local_bus"
  export XDG_RUNTIME_DIR="$RUNDIR"
  export XDG_DATA_HOME="$STATE/data" XDG_CONFIG_HOME="$STATE/cfg"
  export USH_IN_SCOPE=1
  export USH_BROKER_AUTO="${USH_SESSION_VERDICT:-deny}"
  export USH_BROKER_CONFIRM=no
  export USH_BROKER_DECISION_LOG="$DECLOG"

  "$BIN/ush-broker" >"$STATE/broker.log" 2>&1 &
  echo $! >"$STATE/broker.pid"
  for _ in $(seq 1 60); do grep -q "broker: started" "$STATE/broker.log" 2>/dev/null && break; sleep 0.1; done

  # The guest runs a bash command loop reading the FIFO. The outer `while true`
  # reopens the FIFO after each host writer closes (one open/close per command).
  loop='
    while true; do
      while IFS= read -r line; do
        rm -f '"$DONE"'
        eval "$line" > '"$OUT"' 2>&1
        echo $? > '"$RC"'
        : > '"$DONE"'
      done < '"$FIFO"'
    done
  '
  setsid "$BIN/ush" -c "$loop" >"$STATE/guest.log" 2>&1 < /dev/null &
  echo $! >"$STATE/guest.pid"

  # wait until the guest loop is ready (first FIFO open) via a probe command
  sleep 1
  echo "session started. state: $STATE"
  echo "broker verdict: ${USH_BROKER_AUTO}.  drive it with:  $0 run 'whoami'"
  ;;

run)
  shift
  payload="$*"
  [[ -z "$payload" ]] && { echo "usage: $0 run 'CMD'"; exit 2; }
  [[ -p "$FIFO" ]] || { echo "no live session (run '$0 start' first)"; exit 1; }
  rm -f "$DONE"
  # send the command (opens FIFO for write, guest reads, EOF on close)
  if ! timeout 5 bash -c "printf '%s\n' \"\$1\" > '$FIFO'" _ "$payload"; then
    echo "(could not deliver command: guest not reading the FIFO)"; exit 1
  fi
  for _ in $(seq 1 400); do [[ -e "$DONE" ]] && break; sleep 0.05; done
  if [[ ! -e "$DONE" ]]; then
    echo "(timed out waiting for guest; command may be blocking)"; exit 1
  fi
  cat "$OUT"
  echo "[exit $(cat "$RC" 2>/dev/null)]"
  ;;

decisions)
  [[ -f "$DECLOG" ]] && cat "$DECLOG" || echo "(no decisions logged yet)"
  ;;

stop)
  for p in guest broker dbus; do
    [[ -f "$STATE/$p.pid" ]] && kill "$(cat "$STATE/$p.pid")" 2>/dev/null
  done
  # kill the whole guest process group too
  [[ -f "$STATE/guest.pid" ]] && kill -- -"$(cat "$STATE/guest.pid")" 2>/dev/null
  pkill -f "$BIN/ush" 2>/dev/null
  rm -rf "$STATE"
  echo "session stopped, state cleaned"
  ;;

*)
  echo "usage: $0 {start|run 'CMD'|decisions|stop}"
  exit 2
  ;;
esac
