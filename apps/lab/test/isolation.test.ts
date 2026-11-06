import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

for (const vulnerable of [false, true]) {
  describe(vulnerable ? "local vulnerable Worker" : "secure Worker", () => {
    let mf: Miniflare;
    let db: D1Database;
    const tokens = {
      alpha: "test-alpha-credential",
      beta: "test-beta-credential",
    };
    const call = (tenant: keyof typeof tokens, path: string, title?: string) =>
      mf.dispatchFetch(`http://127.0.0.1${path}`, {
        method: title === undefined ? "GET" : "PATCH",
        headers: {
          Authorization: `Bearer ${tokens[tenant]}`,
          "Content-Type": "application/json",
        },
        ...(title === undefined ? {} : { body: JSON.stringify({ title }) }),
      });
    beforeAll(async () => {
      const bundle = await build({
        entryPoints: [vulnerable ? "local/vulnerable.ts" : "src/index.ts"],
        bundle: true,
        metafile: true,
        write: false,
        format: "esm",
        platform: "browser",
      });
      if (!vulnerable)
        expect(
          Object.keys(bundle.metafile.inputs).every(
            (path) => !path.includes("local/"),
          ),
        ).toBe(true);
      mf = new Miniflare(
        convertV4MiniflareOptions({
          modules: true,
          script: bundle.outputFiles[0].text,
          compatibilityDate: "2026-10-30",
          d1Databases: ["DB"],
        }),
      );
      db = await mf.getD1Database("DB");
      const schema = await readFile("migrations/0001_schema.sql", "utf8");
      for (const sql of schema
        .split(";")
        .map((s) => s.trim())
        .filter(Boolean))
        await db.prepare(sql).run();
    });
    afterAll(async () => {
      await mf?.dispose();
    });
    beforeEach(async () => {
      await db.batch(
        [
          "DELETE FROM api_tokens",
          "DELETE FROM documents",
          "DELETE FROM users",
          "DELETE FROM tenants",
        ].map((s) => db.prepare(s)),
      );
      for (const tenant of ["alpha", "beta"] as const) {
        await db
          .prepare("INSERT INTO tenants VALUES (?1,?1)")
          .bind(tenant)
          .run();
        await db
          .prepare("INSERT INTO users VALUES (?1,?1,'Test','tester')")
          .bind(tenant)
          .run();
        await db
          .prepare(
            "INSERT INTO api_tokens(id,user_id,token_hash) VALUES (?1,?1,?2)",
          )
          .bind(
            tenant,
            createHash("sha256").update(tokens[tenant]).digest("hex"),
          )
          .run();
        await db
          .prepare(
            "INSERT INTO documents(id,tenant_id,title,content) VALUES (?1,?2,'original',?3)",
          )
          .bind(
            `${tenant}-doc`,
            tenant,
            `${tenant.toUpperCase()}_PRIVATE_DOCUMENT_MARKER`,
          )
          .run();
      }
    });
    it("rejects invalid credentials", async () => {
      expect(
        (
          await mf.dispatchFetch("http://127.0.0.1/v1/documents", {
            headers: { Authorization: "Bearer invalid" },
          })
        ).status,
      ).toBe(401);
    });
    it("lists only authenticated tenant documents", async () => {
      const response = await call("alpha", "/v1/documents");
      expect(await response.json()).toMatchObject({
        items: [{ id: "alpha-doc", tenant_id: "alpha" }],
      });
    });
    it("establishes legitimate owner access", async () => {
      expect(
        await (await call("beta", "/v1/documents/beta-doc")).json(),
      ).toMatchObject({
        tenant_id: "beta",
        content: "BETA_PRIVATE_DOCUMENT_MARKER",
      });
    });
    it("enforces detail ownership or demonstrates real missing predicate", async () => {
      const response = await call("alpha", "/v1/documents/beta-doc");
      expect(response.status).toBe(vulnerable ? 200 : 404);
      const body = await response.text();
      expect(body.includes("BETA_PRIVATE_DOCUMENT_MARKER")).toBe(vulnerable);
    });
    it("permits legitimate update", async () => {
      expect(
        (await call("beta", "/v1/documents/beta-doc", "legitimate")).status,
      ).toBe(200);
      expect(
        await (await call("beta", "/v1/documents/beta-doc")).json(),
      ).toMatchObject({ title: "legitimate" });
    });
    it("checks actual cross-tenant update state", async () => {
      const response = await call(
        "alpha",
        "/v1/documents/beta-doc",
        "unauthorized-change",
      );
      expect(response.status).toBe(vulnerable ? 200 : 404);
      expect(
        await (await call("beta", "/v1/documents/beta-doc")).json(),
      ).toMatchObject({
        title: vulnerable ? "unauthorized-change" : "original",
      });
    });
    it("checks actual export data", async () => {
      const response = await call("alpha", "/v1/documents/beta-doc/export");
      expect(response.status).toBe(vulnerable ? 200 : 404);
      expect(
        (await response.text()).includes("BETA_PRIVATE_DOCUMENT_MARKER"),
      ).toBe(vulnerable);
    });
    it("rejects client tenant selector", async () => {
      expect((await call("alpha", "/v1/tenants/beta/documents")).status).toBe(
        403,
      );
    });
    it("validates PATCH input", async () => {
      expect(
        (
          await mf.dispatchFetch("http://127.0.0.1/v1/documents/alpha-doc", {
            method: "PATCH",
            headers: {
              Authorization: `Bearer ${tokens.alpha}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ tenant_id: "beta", title: "x" }),
          })
        ).status,
      ).toBe(400);
    });
  });
}
