import { authenticate, json, titleInput, type Document } from "./common";

// The secure deployment graph never imports local/vulnerable.ts.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET")
      return json({ status: "ok" });
    const identity = await authenticate(request, env);
    if (!identity) return json({ error: "Unauthorized" }, 401);
    const tenant = identity.tenant_id;
    if (url.pathname === "/v1/documents" && request.method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT * FROM documents WHERE tenant_id=?1 ORDER BY id LIMIT 100",
      )
        .bind(tenant)
        .all<Document>();
      return json({ items: rows.results });
    }
    const collection = /^\/v1\/tenants\/([^/]+)\/documents$/.exec(url.pathname);
    if (collection && request.method === "GET") {
      if (decodeURIComponent(collection[1]) !== tenant)
        return json({ error: "Forbidden" }, 403);
      const rows = await env.DB.prepare(
        "SELECT * FROM documents WHERE tenant_id=?1 ORDER BY id LIMIT 100",
      )
        .bind(tenant)
        .all<Document>();
      return json({ items: rows.results });
    }
    const match = /^\/v1\/documents\/([^/]+)(\/export)?$/.exec(url.pathname);
    if (!match) return json({ error: "Not found" }, 404);
    const id = decodeURIComponent(match[1]);
    if (request.method === "PATCH" && !match[2]) {
      const title = await titleInput(request);
      if (title === null)
        return json(
          { error: "Expected only a nonempty title of at most 200 characters" },
          400,
        );
      const row = await env.DB.prepare(
        "UPDATE documents SET title=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2 AND tenant_id=?3 RETURNING *",
      )
        .bind(title, id, tenant)
        .first<Document>();
      return row ? json(row) : json({ error: "Not found" }, 404);
    }
    if (request.method !== "GET")
      return json({ error: "Method not allowed" }, 405);
    // The export and detail routes use exactly the same ownership predicate.
    const row = await env.DB.prepare(
      "SELECT * FROM documents WHERE id=?1 AND tenant_id=?2",
    )
      .bind(id, tenant)
      .first<Document>();
    return row
      ? json(match[2] ? { documents: [row] } : row)
      : json({ error: "Not found" }, 404);
  },
} satisfies ExportedHandler<Env>;
