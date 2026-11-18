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

## Device- and environment-specific code

Code that exists only because of a specific device, architecture, firmware or environment must be marked on the line above it:

```
DEVICE-FIX(<scope>): <what breaks without this>
```

- `<scope>` is one of: `arm64`, `x86_64`, `uno-q`, `jetson`, `msm`, `nvidia`, `intel`, `amd`, `no-tpm`, `vm`, `u-boot`, `uefi`. A new scope is added to this list in the same pull request that first uses it.
- The text states what fails on that device without the code, not what the code does.
- Use the comment syntax of the file's language.
- This covers driver names, hardware probes, architecture constants, firmware quirks, boot-chain differences and anything gated on a specific environment.
- A pull request that adds or changes such code without the marker is not merged.
- `git grep -n "DEVICE-FIX("` lists every marker in the repository.
