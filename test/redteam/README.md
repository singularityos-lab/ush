# USH red-team harness

A repeatable way to drive `ush` non-interactively **and** answer broker
permission requests programmatically, so security scenarios (including breach
attempts) can be replayed and asserted without a human at a GUI dialog.

It has two parts:

1. **Broker AUTO mode** (`internal/broker/auto.go`). When the broker process is
   started with `USH_BROKER_AUTO` set, it skips every GUI/terminal dialog and
   decides from a default verdict plus an optional ordered rules file, recording
   every decision to a JSONL log. This is the "accept permissions outside the
   broker" capability. It is gated behind an explicit env var and is never the
   default, so it cannot weaken a normal install.

2. **The harness** (`run.sh`). For each scenario it starts a *private*
   `dbus-daemon`, a broker in AUTO mode, and an `ush -c "<script>"` guest, all on
   an isolated bus and a clean per-scenario storage dir. It then asserts on the
   guest output and the broker decision log.

## Run

```sh
test/redteam/run.sh          # run all scenarios
KEEP=1 test/redteam/run.sh   # keep the work dir (under /tmp) for inspection
```

Requirements on the host: `go`, `dbus-daemon`, unprivileged user namespaces,
and (for the network scenarios) `curl` / `python3`. Landlock and `pasta` are not
required; the harness adapts when they are absent.

## Broker AUTO mode environment

| Variable                  | Meaning                                                         |
|---------------------------|----------------------------------------------------------------|
| `USH_BROKER_AUTO`         | default verdict (`allow`/`deny`/`allow_session`/`allow_always`); presence enables AUTO mode |
| `USH_BROKER_RULES`        | path to a JSON rules file; first match wins, else the default  |
| `USH_BROKER_CONFIRM`      | `yes`/`no` answer for the AllowApp / RevokePermission confirmation gates |
| `USH_BROKER_DECISION_LOG` | path to a JSONL file that records every decision (the attack trace) |

Rules file format (ordered, first match wins):

```json
[
  { "category": "network", "resource": "tcp://1.1.1.1:443", "match": "exact",  "decision": "allow" },
  { "category": "network", "resource": "tcp://10.",          "match": "prefix", "decision": "deny"  },
  { "category": "device",  "resource": "/dev/sd",            "match": "prefix", "decision": "deny"  }
]
```

`match` is one of `exact` (default), `prefix`, `substr`, `regex`. An empty
`category` matches any category.

## Scenarios

| ID  | What it checks |
|-----|----------------|
| S1  | Default-deny actually denies a network permission request (broker round-trip via the `perm` builtin) |
| S2  | A rules file selectively allows one resource, logged with the matched rule index |
| S3  | A guest **cannot** silently self-trust an app: `AllowApp` requires confirmation |
| S3b | A confirmed trust persists, keyed on the absolute exe path |
| S4  | A real outbound `connect()` is intercepted at the syscall layer and routed to the broker |
| B1  | **Breach attempt**: a process fakes its `comm` to a trusted app name; trust is keyed on `/proc/<pid>/exe`, so it does not inherit the trust and the connection is denied |
| B2  | **Breach attempt**: link-local metadata `169.254.169.254` is no longer auto-allowed and goes through the broker |

The harness is a genuine regression detector, not a smoke test: reverting the
exe-based trust to the old `comm`-based check makes B1 report
`SPOOF_CONNECTED` with no broker decision logged, i.e. a real breach.

## Adding a scenario

Set `AUTO` / `CONFIRM` / `RULES` / `SEED_POLICY` and a `SCRIPT` (the string
passed to `ush -c`), call `run_scenario <tag>`, then assert with `guest_has`,
`declog_has`, or by inspecting `policy_file <tag>`.
