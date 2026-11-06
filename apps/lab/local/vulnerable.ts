// DELIBERATELY VULNERABLE. Imported only by the loopback Miniflare launcher.
// Never add this module to the secure Worker's deployment graph.
import { authenticate, json, titleInput, type Document } from "../src/common";
import secure from "../src/index";
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (
      !["127.0.0.1", "localhost", "[::1]"].includes(
        new URL(request.url).hostname,
      )
    )
      return json({ error: "Local lab only" }, 403);
    const match = /^\/v1\/documents\/([^/]+)(\/export)?$/.exec(
      new URL(request.url).pathname,
    );
    if (!match) return secure.fetch(request, env);
    if (!(await authenticate(request, env)))
      return json({ error: "Unauthorized" }, 401);
    const id = decodeURIComponent(match[1]);
    if (request.method === "PATCH" && !match[2]) {
      const title = await titleInput(request);
      if (title === null) return json({ error: "Invalid title" }, 400);
      // B: Authentication exists, but the UPDATE omits tenant ownership.
      const row = await env.DB.prepare(
        "UPDATE documents SET title=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2 RETURNING *",
      )
        .bind(title, id)
        .first<Document>();
      return row ? json(row) : json({ error: "Not found" }, 404);
    }
    if (request.method !== "GET")
      return json({ error: "Method not allowed" }, 405);
    // A and C: Both detail and export forget the tenant predicate.
    const row = await env.DB.prepare("SELECT * FROM documents WHERE id=?1")
      .bind(id)
      .first<Document>();
    return row
      ? json(match[2] ? { documents: [row] } : row)
      : json({ error: "Not found" }, 404);
  },
} satisfies ExportedHandler<Env>;
