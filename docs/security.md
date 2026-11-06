# Security model and authorized use

Run only against APIs you own or have explicit permission to test. `run --authorized` is mandatory. Origin allowlists limit the request destination; they are not proof of legal authorization. Use two controlled test tenants containing private synthetic disposable fixtures. `inspect` is offline.

PATCH tests have real effects. The test writes a unique string, reads as the owner, restores the original field through the owner endpoint and verifies it. No write is automatically retried. Network timeouts can happen after the server committed a change, so read-back and restoration still occur. The request budget reserves cleanup attempts before writing. An unknown state triggers best-effort restoration. Cleanup failure stops execution, preserves findings and forces exit 2.

Host termination, asynchronous API side effects, concurrent fixture edits or irreversible request-template fields can prevent restoration. Reset isolated fixtures after interruption. This MVP has no durable recovery journal and cannot undo notifications, external jobs or arbitrary API side effects. Never map such operations.

## Data handling

Credentials are environment-only bearer tokens, not configuration values. The tool never stores authorization headers, cookies or raw response bodies. Responses are streamed within a byte bound. Proof descriptions omit synthetic content, original mutable values and full exports. Known credential values are additionally scrubbed across report string fields. Resource IDs, tenant labels, request paths, environment variable names and target labels remain visible: they must be nonsecret test metadata. Review reports before sharing them. Operator-supplied configuration/specification files and errors are not a secret vault; do not put secret values in them.

HTML escapes dynamic content and uses no remote fonts, scripts or styles. A restrictive meta CSP disables external resources. JSON report input is size-limited and deserialized into a strict versioned schema before rendering. Reports do not replay requests.

## Execution scope

Remote targets require HTTPS; certificate verification is never disabled. Only explicit loopback hosts can use HTTP. Redirects and environment proxies are disabled. Path/query substitutions are encoded and final origins checked. Request count, rate, timeout, retries and body size are bounded. Only explicitly mapped GET/PATCH operations run. Unmapped endpoints, DELETEs and arbitrary fuzzing are never executed.

DNS resolution is trusted; origin restrictions do not prevent an operator-selected hostname resolving to a private address. Use network isolation if operating on untrusted configurations. Local file paths are operator-controlled. OpenAPI network refs are never followed. The engine uses exact synthetic marker matching: false confidence is possible if operators label public/nonunique content as private. Passes apply only to selected fixtures, initial pages and configured operations.

## Vulnerable lab

The vulnerable module is separate from the normal deployment dependency graph. Its only launcher is local Miniflare bound to 127.0.0.1, with an additional host check in the handler. There is no vulnerable Wrangler deployment configuration. Do not modify it into a public service, run a tunnel, or forward it through an externally accessible reverse proxy. Seed credentials are generated randomly, local files are ignored, and only SHA-256 hashes enter D1. Resetting seeds rotates credentials.

See [SECURITY.md](../SECURITY.md) for reporting defects in TenantFence. Use the target application's own disclosure channel for findings in other services. Avoid publishing credentials, customer data or exploit details before coordinating a fix.
