# Interpreting findings

| Status       | Evidence                                                                                                               |
| ------------ | ---------------------------------------------------------------------------------------------------------------------- |
| passed       | Declared denial without known private markers; or declared empty collection; PATCH also verifies unchanged owner state |
| failure      | Exact owner-verified private marker appears to the other tenant, or owner read-back verifies unauthorized modification |
| inconclusive | Ambiguous response, missing per-operation baseline, unsupported content or success without state change                |
| skipped      | Explicitly mapped category disabled                                                                                    |
| error        | Transport/body/budget failure or unsafe completion                                                                     |

Confirmed failures have high severity and confirmed confidence because they expose private fixture data or allow an unauthorized state change. Passed results use verified confidence; uncertainty is never converted into a confirmed failure. The configured synthetic marker is the evidence anchor; HTTP 200 alone proves nothing.

Each result has a stable resource/category/owner-index/fixture-ID test ID, operation and request path, requester/owner labels, policy, observed behavior, sanitized proof description, status/timing/body size, remediation and reproduction context. Raw private values are omitted. Read-only curl examples reference the configured environment variable and do not follow redirects. Mutation reproduction describes the entire safe owner-read/attack/read-back/restore procedure rather than offering a blind write command.

## D1 remediation

Authentication establishes who called. Every resource access must separately establish whether that identity may access that object. A filtered collection does not protect a detail route, update or export.

```ts
// Vulnerable: bound parameters prevent injection, but any authenticated tenant can read an ID.
DB.prepare("SELECT * FROM documents WHERE id=?1").bind(id);
// Secure: the tenant comes from server-side authentication.
DB.prepare("SELECT * FROM documents WHERE id=?1 AND tenant_id=?2").bind(
  id,
  identity.tenant_id,
);

// Vulnerable unauthorized update.
DB.prepare("UPDATE documents SET title=?1 WHERE id=?2").bind(title, id);
// Secure ownership check is part of the atomic update.
DB.prepare("UPDATE documents SET title=?1 WHERE id=?2 AND tenant_id=?3").bind(
  title,
  id,
  identity.tenant_id,
);
```

Use the same authorization invariant for export queries and all rows in exported collections. Never substitute a client-provided tenant selector for the authenticated tenant. A tenant-scoped collection URL must first authorize its selector and still bind the server-side tenant in SQL. Parameterized D1 queries help prevent SQL injection; they do not add tenant predicates automatically.

TenantFence cannot infer these SQL mistakes from HTTP evidence. The lab demonstrates them directly; real applications must inspect their actual ownership enforcement. Verify fixes by rerunning both legitimate owner baselines and both adversarial directions.
