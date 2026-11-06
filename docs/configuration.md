# Configuration reference

Every object rejects unknown keys. All fields below are required unless marked optional. Paths resolve relative to the YAML file. JSON is also accepted as a YAML subset. See the complete runnable [lab configuration](../examples/cloudflare-d1/tenantfence.yaml).

## Target

| Field                | Meaning                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `label`              | Nonsecret display identifier; included in reports                                                  |
| `spec`               | Local OpenAPI file path                                                                            |
| `base_url`           | Origin only, no path prefix, credentials, query or fragment; include API prefixes in OpenAPI paths |
| `allowed_origins`    | Explicit canonical origins, including scheme and port; must contain base origin                    |
| `timeout_ms`         | Per-attempt timeout including response streaming, 1–120000                                         |
| `max_response_bytes` | Hard streaming response bound, 1–16777216                                                          |

TLS certificate verification is always enabled. HTTPS is mandatory except literal localhost, 127.0.0.1 or ::1. Redirects are always disabled, including same-origin redirects. Environment proxies are disabled. These are fixed security controls, not configurable bypasses. URLs are built from OpenAPI path templates; values are encoded as path segments or query pairs. Literal dot segments are rejected.

The allowlist authorizes origins, not resolved network ranges. DNS is trusted; do not use untrusted hostnames or run with network privileges beyond the intended target. A base URL with a path prefix is deliberately rejected to avoid ambiguous route joining.

## Tenants

Exactly two entries: `name` (distinct logical label), `selector` (distinct ownership field value) and `token_env` (valid environment variable name). `headers` is an optional string map of explicitly permitted nonsecret X- headers. Authentication/token/key headers, Host and cookies are not accepted here. Bearer credentials are read only when running, must differ, and are never serialized. Header values must be valid HTTP header values.

## Resources

Each entry declares a private resource type. Names must be unique.

| Field                      | Meaning                                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------- |
| `name`                     | Resource label                                                                                            |
| `discovery`                | Optional GET operationId; required unless both tenants have explicit fixtures                             |
| `fixtures`                 | Optional map from tenant logical name to nonempty resource ID arrays; overrides discovery for that tenant |
| `collection_pointer`       | JSON Pointer to collection array; `""` for root array                                                     |
| `id_pointer`               | JSON Pointer to ID on individual collection/detail objects; string or numeric ID                          |
| `read`                     | Owner detail GET operationId                                                                              |
| `id_parameter`             | Declared path or query parameter receiving fixture ID                                                     |
| `owner_pointer`            | Detail JSON Pointer to authenticated tenant ownership value; must match `selector`                        |
| `marker_pointer`           | Detail JSON Pointer to private unique synthetic string, at least 12 bytes                                 |
| `collection`               | Optional scoped collection GET operationId                                                                |
| `tenant_parameter`         | Declared path/query tenant selector; required with collection                                             |
| `export`                   | Optional synchronous export GET operationId                                                               |
| `export_format`            | Optional `json` (default) or `csv`                                                                        |
| `mutation`                 | Optional disposable PATCH mapping (below)                                                                 |
| `denial_statuses`          | Nonempty accepted subset of `[403, 404]`                                                                  |
| `empty_collection_allowed` | Optional false by default; accepts 2xx with empty configured collection array                             |
| `parameters`               | Optional string map for additional declared path/query parameter values                                   |

Operation methods must match mappings. Required unsupported header/cookie parameters are rejected. Additional required path/query parameters must be supplied. No arbitrary request generation occurs for unmapped operations; `inspect` lists them as skipped. Public resources should not be mapped. Initial collection pages only are inspected. Empty discovery is an unavailable baseline, not a passing isolation assertion.

Explicit fixture example (omit discovery if unavailable):

```yaml
fixtures:
  alpha: [alpha-disposable-document]
  beta: [beta-disposable-document]
```

Ownership is verified using owner credentials, the exact returned ID and the declared tenant selector, never identifier naming. IDs and markers must be distinct across the resource's two tenant fixtures. Collection and export operations have their own owner baselines before adversarial testing.

## Mutation

`operation` is an explicit PATCH operationId with JSON requestBody. `disposable: true` is mandatory. `value_pointer` selects the original mutable value in the owner detail response. `body_pointer` selects that value in `body`, the JSON request template. The pointer must already exist. Owner restoration submits the same template with the original mutable value.

```yaml
mutation:
  operation: updateDocument
  disposable: true
  value_pointer: /title
  body_pointer: /title
  body: { title: placeholder }
  # Optional: substitute declared IDs/selectors into explicit body fields.
  # body_parameters: {/document_id: documentId, /tenant_id: tenantId}
```

`body_parameters` maps existing JSON Pointers to configured parameter names (`id_parameter`, `tenant_parameter`, or `parameters` keys). Include those fields in the body template and describe them in OpenAPI. Only include safe fields; the template must not have unrelated side effects. Avoid side effects such as notifications and asynchronous jobs, which this tool cannot undo. The mutable field must accept a string test marker. Mutation requires **both** this mapping and `execution.writes: true`. PATCH requests are never retried.

The runner reserves sufficient request budget for pre-read, attack, read-back, restoration and verification before dispatching a write. Read-back after a timeout still runs. Ambiguous state triggers restoration; verified unchanged state needs no restoration. Cleanup failure stops further testing, records an error and forces exit 2. An abrupt process/host failure cannot guarantee restoration.

## Execution

| Field                      | Meaning                                                                        |
| -------------------------- | ------------------------------------------------------------------------------ |
| `max_requests`             | Total attempts including baselines, retries and cleanup; 1–100000              |
| `max_resources_per_tenant` | Initial-page fixture cap per resource and tenant, 1–100                        |
| `max_concurrency`          | Must be 1 in this MVP to keep fixture mutations serial                         |
| `requests_per_second`      | Global start-rate cap, 1–100                                                   |
| `safe_retries`             | GET transport/429/5xx retries only, 0–2; rate and request bounds apply         |
| `writes`                   | Enable explicit disposable mutation mappings                                   |
| `exports`                  | Enable explicitly mapped synchronous exports                                   |
| `required`                 | Categories that must be conclusive: `read`, `collection`, `mutation`, `export` |

Required disabled/unmapped categories fail validation. Required inconclusive/skipped tests force exit 2. All runtime errors and baseline failures force exit 2 even for optional categories. Redaction is mandatory: raw response bodies, headers, token values and private markers are not retained in reports. Only proof descriptions and bounded metadata are retained. Effective execution controls appear in reports.

## Common modes

Read-only: set `writes: false`, `exports: false`, `required: [read]`. Keep optional mappings to see explicitly skipped configured tests, or remove them. Add `collection` to required when scoped collection coverage matters.

Exports: configure `export`, choose JSON/CSV, enable `exports`, require `export`. Exact baseline markers must appear as complete JSON strings or CSV cell values. Owner exports without a verifiable marker are inconclusive. Legitimate owner exports are also checked for the other tenant’s independently verified markers; mixed-tenant content produces a separate confirmed export finding even when cross-ID requests are denied. Asynchronous/binary exports are unsupported.

External authorized API: use an explicit HTTPS origin in both `base_url` and `allowed_origins`, private test tenants, environment credentials, and fixture ownership/marker mappings matching real response shapes. Run `inspect` first, then `run --authorized`. The [generic example](../examples/generic-api/tenantfence.yaml) shows query IDs and supplied fixtures. No custom policy scripting is supported.
