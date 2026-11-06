# Architecture

TenantFence is one Rust library/binary package with cohesive modules rather than a plugin framework.

1. `config` parses strict typed configuration, validates safe limits, resolves specification paths and loads two environment credentials at execution time.
2. `spec` normalizes OpenAPI 3.0/3.1 path/method/operation IDs, inherited parameters, request body descriptions and security metadata. Local JSON Pointer references are resolved with cycle/depth limits. External references are never fetched. Unmapped operations are advisory only.
3. `http` encodes path/query substitutions and enforces the configured origin, verified TLS, no redirects or environment proxy, streamed response bounds, timeout, serial rate limit and global attempt budget.
4. `engine` discovers bounded fixtures, validates owner IDs/ownership/synthetic markers, refreshes baselines, constructs the other tenant's request and classifies deterministic evidence. Explicit PATCH templates support body field substitutions. The authentication identity never changes to match a forged selector.
5. `report` shares a typed versioned model between terminal/JSON/static HTML. All dynamic HTML text is escaped. No raw response bodies are persisted. Known credential values are replaced across serialized string fields as an additional defense.

Discovery happens for both tenants before adversarial requests. Overlapping IDs or markers invalidate the resource baseline. Owner detail reads prove resource identity; owner collections and exports prove the mapped operation can deliver the expected fixture marker. Missing baselines are errors/inconclusive coverage, never findings.

Reads, collections and exports use exact known private markers decoded from JSON or CSV. Denial statuses are accepted only after inspecting the bounded body for protected markers; malformed nonempty denial bodies are inconclusive. An ambiguous 200 is inconclusive. Mutation confirmation is independent of the PATCH status: only owner read-back of the unique attempted value confirms the change. Cleanup verification has a reserved request budget. Cleanup failure stops testing and forces an error outcome, while retaining any confirmed finding.

## Trust boundaries

The operator authorizes the target and controls both tenants, fixture ownership and private synthetic markers. Credentials are secret, in memory only. The API, OpenAPI paths and all response/report content are treated as untrusted input. URL origin validation occurs after URL construction. DNS/host configuration, the local filesystem and operator configuration are trusted. Never run against attacker-controlled domains with privileged network access.

This tool is not a SQL observer and cannot identify which query or framework caused an exposure. It proves only the observed fixture behavior, not universal absence of authorization defects.

## D1 lab

The secure Worker authenticates SHA-256 hashes of randomly generated local bearer tokens, deriving tenant identity from a token/user join. Prepared statements bind resource ID **and** authenticated tenant ID on detail, export and update routes. The scoped collection route rejects a foreign selector. The schema includes tenants, users, token hashes and documents with foreign keys/indexes.

The separate `local/vulnerable.ts` omits ownership predicates on three real queries. It is bundled only by a loopback Miniflare launcher and has a host guard. The Wrangler configuration imports only `src/index.ts`; there is no deployment flag selecting vulnerable handlers. The example configuration uses disposable documents and never creates cloud resources. Wrangler and its exact companion Miniflare version (currently a prerelease) are pinned together to keep configuration and D1 persistence compatible; update and test them together. The compatibility date matches the newest date supported by the bundled runtime.

## Deliberate limits

Single process, serial execution; first configured collection page; two bearer tenants; non-cyclic local refs; no complete schema validation; no schema-driven fuzzing; synchronous JSON/CSV exports; no persistent cleanup journal after host termination. References are resolved only for relevant path operations, so unused components are not exhaustively validated. Required category flags allow CI to reject untrustworthy incomplete coverage.
