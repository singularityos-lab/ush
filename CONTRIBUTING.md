# Contributing to ush

Thanks for your interest in contributing.

## Quick start

```bash
git clone https://github.com/singularityos-lab/ush
cd ush
make build   # builds the LD_PRELOAD shim, ush and ush-broker
make test
```

`make build` builds `ush` and `ush-broker` with the version ldflag, so use it
(not a bare `go build`) to get a correct version string. The `LD_PRELOAD` shim
the package layer relies on is embedded as C source in `internal/preload` and
compiled at runtime inside the guest, so it needs no separate build step.

## Ground rules

- Keep the host/guest boundary explicit: anything crossing it goes through the
  broker with a policy decision, never an implicit privilege.
- `dsh` is a convenience profile, not a security boundary. Do not rely on it for
  isolation, and do not weaken the `ush` profile to make `dsh` easier.
- Run `make fmt vet test` before opening a pull request.

## License and CLA

Contributions are licensed under GPLv3-only. By opening a pull request you agree
to the [CLA](CLA.md).
