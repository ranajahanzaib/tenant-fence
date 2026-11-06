import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
process.chdir(fileURLToPath(new URL("..", import.meta.url)));
const sql = [
  "DELETE FROM api_tokens; DELETE FROM documents; DELETE FROM users; DELETE FROM tenants;",
];
const credentials = {};
for (const tenant of ["alpha", "beta"]) {
  const token = randomBytes(32).toString("hex");
  credentials[`TENANTFENCE_${tenant.toUpperCase()}_TOKEN`] = token;
  const hash = createHash("sha256").update(token).digest("hex");
  sql.push(`INSERT INTO tenants VALUES ('${tenant}','${tenant}');`);
  sql.push(
    `INSERT INTO users VALUES ('${tenant}-user','${tenant}','Lab user','tester');`,
  );
  sql.push(
    `INSERT INTO api_tokens(id,user_id,token_hash) VALUES ('${tenant}-token','${tenant}-user','${hash}');`,
  );
  for (let i = 1; i <= 2; i++)
    sql.push(
      `INSERT INTO documents(id,tenant_id,title,content) VALUES ('${tenant}-doc-${i}','${tenant}','Disposable ${i}','${tenant.toUpperCase()}_PRIVATE_DOCUMENT_MARKER_${i}');`,
    );
}
mkdirSync(".local", { recursive: true });
writeFileSync(".local/seed.sql", sql.join("\n"), { mode: 0o600 });
for (const args of [
  ["d1", "migrations", "apply", "tenantfence-lab", "--local"],
  ["d1", "execute", "tenantfence-lab", "--local", "--file", ".local/seed.sql"],
]) {
  const result = spawnSync(
    "node",
    ["node_modules/wrangler/bin/wrangler.js", ...args],
    { stdio: "inherit" },
  );
  if (result.status !== 0) process.exit(result.status ?? 2);
}
writeFileSync(".local/credentials.json", JSON.stringify(credentials), {
  mode: 0o600,
});
writeFileSync(
  ".local/tokens.env",
  Object.entries(credentials)
    .map(([key, value]) => `export ${key}='${value}'`)
    .join("\n") + "\n",
  { mode: 0o600 },
);
console.log(
  "Local D1 fixtures reset. Credentials written to .local/tokens.env (values not printed).",
);
