# Contributing

Use stable Rust and Node.js 22.12+ and pnpm 10 on macOS or Linux. Run `make setup`, then `make check`. Tests do not require a Cloudflare account, paid services or Docker. Port 8787 must be available for end-to-end tests.

Rust code lives in `src/`; core evaluation should stay independently testable from HTTP. Use typed strict configuration, actionable error contexts, bounded operations and no runtime unwrap/expect on untrusted input. Add mock HTTP coverage for changes to request generation, evidence classification, budgets and cleanup.

The lab is in `apps/lab/`. Use strict TypeScript, generated Wrangler runtime types, bound D1 statements and server-derived ownership predicates. `pnpm --dir apps/lab format` formats source and tests; `cargo fmt` formats Rust. Run `pnpm --dir apps/lab types` after binding/config changes. Generated runtime types are not manually edited. Keep the intentionally vulnerable local module out of the secure deployment graph.

For security behavior changes, test actual protected content and owner state, not only status codes. Add regression tests for ambiguity and failed baselines. Never commit credentials, `.local`, `.wrangler`, customer data or raw export bodies. Review generated reports for sanitization before sharing them. Prefer small focused changes and document configuration/schema changes and limitations.

Report issues with tool versions, a sanitized configuration and minimal reproducible synthetic fixtures. See SECURITY.md for sensitive vulnerabilities. Follow CODE_OF_CONDUCT.md.
