# Continuous integration

`make check` performs fmt, warning-denied Clippy on all Rust targets, Rust unit/mock HTTP tests, Prettier, strict TypeScript checks, real Miniflare D1 Worker tests, and the actual local Worker/D1 end-to-end script. CI uses stable Rust and Node 22, lockfiles, a bounded job timeout and read-only repository permissions. No Cloudflare credentials are required.

`node scripts/e2e.mjs` applies local D1 migrations, idempotently resets fixtures with random hashed tokens, waits up to 45 seconds per Worker health check, runs the real binary, asserts exit codes and actual owner state, regenerates HTML and checks redaction. Secure and vulnerable processes are terminated as a process group in a finally block. It refuses an already occupied lab port. Worker logs stay local; CI uploads only sanitized JSON/HTML.

For your own authorized API, supply credential environment variables via the CI secret store, then run:

```sh
tenantfence inspect --config tenantfence.yaml
tenantfence run --authorized --config tenantfence.yaml --output reports
```

Treat exit 1 as confirmed exposure, exit 2 as untrustworthy/incomplete execution. A cleanup failure takes precedence over confirmed findings and must be investigated. Optional inconclusive/skipped categories stay in reports but do not force an error; declare deployment-critical categories in `execution.required`. Baseline and runtime errors always fail CI.

If your shell has an older standalone `rustdoc` ahead of rustup's toolchain, run `RUSTDOC="$(rustup which rustdoc)" cargo test --locked` or put rustup shims first in PATH. Keep rustc/rustdoc from the same toolchain.
