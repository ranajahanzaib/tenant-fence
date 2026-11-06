.PHONY: setup seed secure vulnerable test test-rust test-worker e2e reports check
setup:
	cargo fetch --locked
	pnpm install --dir apps/lab --frozen-lockfile
seed:
	pnpm --dir apps/lab prepare:db
secure:
	pnpm --dir apps/lab dev
vulnerable:
	pnpm --dir apps/lab dev:vulnerable
test-rust:
	cargo test --locked
test-worker:
	pnpm --dir apps/lab test
test: test-rust test-worker
e2e reports:
	node scripts/e2e.mjs
check:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked
	pnpm --dir apps/lab lint
	pnpm --dir apps/lab typecheck
	pnpm --dir apps/lab test
	node scripts/e2e.mjs
