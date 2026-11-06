# JSON report v1

Reports use strict serde structures in `src/report.rs`; `tenantfence report` validates version, required fields, enums, test IDs, categories, severity and confirmed-failure confidence. Unknown object fields are rejected. Missing required fields or unsupported schema versions return exit 2. JSON input is capped at 32 MiB.

Top-level fields:

| Field                | Type / contract                                                                 |
| -------------------- | ------------------------------------------------------------------------------- |
| schema_version       | Integer, exactly 1                                                              |
| tool_version         | Nonempty semantic version string                                                |
| target               | Nonsecret display identifier                                                    |
| started_unix_seconds | Unsigned Unix time                                                              |
| duration_ms          | Nonnegative elapsed wall time                                                   |
| requests             | Total HTTP attempts including baselines/retries/cleanup                         |
| safe_settings        | Effective execution configuration                                               |
| safe_network         | Effective origin, timeout, response limit and fixed TLS/redirect/proxy controls |
| coverage             | Array of scope/limitation descriptions                                          |
| results              | Ordered test-result objects, including confirmed failures                       |
| errors               | Baseline/cleanup/execution error summaries                                      |

Each result contains string fields `id`, `category`, `resource`, `operation_id`, `method`, `path`, `attacker`, `owner`, `expected`, `actual`, `severity`, `confidence`, `reproduction`, `remediation`, `impact`; `status` is `passed`, `failure`, `inconclusive`, `skipped` or `error`; `evidence` is a map of sanitized string metadata; `cleanup` is nullable string; `required` is boolean. Categories are `read`, `collection`, `mutation`, `export`. Severity is `high` for confirmed failures, otherwise `info`. Confidence is `confirmed`, `verified`, or `inconclusive`.

Confirmed findings are `results` entries with `status == "failure"`; cleanup outcomes live on those same result objects. Error summaries are top-level `errors` plus result entries with status `error`. This avoids divergent duplicate finding/cleanup lists. Deterministic configuration order produces stable result order and IDs; times and unique mutation markers naturally vary. Mutation markers themselves are not serialized.

Evidence contains HTTP status, bounded byte count, timing and proof descriptions, never raw responses. Reports always omit credential values, original mutable values and full exports. Paths and fixture identifiers remain visible and must be nonsecret. Future incompatible changes increment `schema_version`.
