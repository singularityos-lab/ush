# Contributing to ush

Thanks for your interest in contributing.

## Quick start

```bash
git clone https://github.com/singularityos-lab/ush
cd ush
make build   # builds the LD_PRELOAD shim, ush and ush-broker
make test
```

`make build` compiles the `LD_PRELOAD` shim from
`internal/preload/csrc/ush-chown-shim.c` into a prebuilt `.so` and builds `ush`
and `ush-broker` with the version ldflag, so run it (not a bare `go build`) after
a fresh clone. The same C source is embedded in the binary and compiled at
runtime inside the guest when a compiler is available; the prebuilt `.so` is the
fallback for hosts without one.

## Ground rules

- Keep the host/guest boundary explicit: anything crossing it goes through the
  broker with a policy decision, never an implicit privilege.
- `dsh` is a convenience profile, not a security boundary. Do not rely on it for
  isolation, and do not weaken the `ush` profile to make `dsh` easier.
- Run `make fmt vet test` before opening a pull request.

## License and CLA

Contributions are licensed under GPLv3-only. By opening a pull request you agree
to the [CLA](CLA.md).
