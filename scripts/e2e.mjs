import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("..", import.meta.url));
process.chdir(root);
const lab = `${root}/apps/lab`;
const env = {
  ...process.env,
  WRANGLER_SEND_METRICS: "false",
  WRANGLER_LOG_PATH: `${lab}/.local/wrangler.log`,
};
function command(cmd, args, cwd = root, extraEnv = {}) {
  const result = spawnSync(cmd, args, {
    cwd,
    env: { ...env, ...extraEnv },
    stdio: "inherit",
  });
  if (result.status !== 0) throw new Error(`${cmd} failed (${result.status})`);
}
command("cargo", ["build", "--locked"]);
command("node", ["scripts/seed.mjs"], lab);
const credentials = JSON.parse(
  readFileSync(`${lab}/.local/credentials.json`, "utf8"),
);
mkdirSync("reports", { recursive: true });
async function healthy(child) {
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null)
      throw new Error(
        "Worker exited before ready; inspect reports/*-worker.log",
      );
    try {
      const r = await fetch("http://127.0.0.1:8787/health", {
        signal: AbortSignal.timeout(700),
      });
      if (r.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Worker health deadline exceeded");
}
// Refuse to attach to another service or accidentally test an unrelated listener.
try {
  await fetch("http://127.0.0.1:8787/health", {
    signal: AbortSignal.timeout(500),
  });
  throw new Error("Port 8787 is already occupied; stop the lab first");
} catch (e) {
  if (e.message.includes("occupied")) throw e;
}
for (const mode of ["secure", "vulnerable"]) {
  const fd = openSync(`reports/${mode}-worker.log`, "w");
  const args =
    mode === "secure"
      ? [
          "node_modules/wrangler/bin/wrangler.js",
          "dev",
          "--local",
          "--ip",
          "127.0.0.1",
          "--port",
          "8787",
        ]
      : ["scripts/vulnerable.mjs"];
  const child = spawn("node", args, {
    cwd: lab,
    env,
    stdio: ["ignore", fd, fd],
    detached: true,
  });
  try {
    await healthy(child);
    const result = spawnSync(
      `${root}/target/debug/tenantfence`,
      [
        "run",
        "--config",
        "examples/cloudflare-d1/tenantfence.yaml",
        "--authorized",
        "--output",
        `reports/${mode}`,
      ],
      { env: { ...env, ...credentials }, stdio: "inherit" },
    );
    assert.equal(
      result.status,
      mode === "secure" ? 0 : 1,
      `${mode} CLI exit code`,
    );
    const report = JSON.parse(
      readFileSync(`reports/${mode}/report.json`, "utf8"),
    );
    assert.equal(report.results.length, 16);
    assert.deepEqual(report.errors, []);
    if (mode === "secure")
      assert(report.results.every((r) => r.status === "passed"));
    else
      for (const category of ["read", "mutation", "export"]) {
        const findings = report.results.filter(
          (r) => r.category === category && r.status === "failure",
        );
        assert.equal(findings.length, 4, category);
        for (const finding of findings) {
          assert.equal(finding.confidence, "confirmed");
          assert(Object.keys(finding.evidence).length > 0);
          if (category === "mutation")
            assert.equal(finding.cleanup, "restored and verified");
        }
      }
    for (const tenant of ["alpha", "beta"]) {
      const token = credentials[`TENANTFENCE_${tenant.toUpperCase()}_TOKEN`];
      const response = await fetch("http://127.0.0.1:8787/v1/documents", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const { items } = await response.json();
      assert(
        items.every((d) => d.title.startsWith("Disposable ")),
        "fixture restoration",
      );
    }
    const json = readFileSync(`reports/${mode}/report.json`, "utf8");
    const html = readFileSync(`reports/${mode}/report.html`, "utf8");
    for (const token of Object.values(credentials)) {
      assert(!json.includes(token));
      assert(!html.includes(token));
    }
    assert(
      !json.includes("BETA_PRIVATE_DOCUMENT_MARKER"),
      "raw protected data omitted",
    );
    command(`${root}/target/debug/tenantfence`, [
      "report",
      "--input",
      `reports/${mode}/report.json`,
      "--output",
      `reports/${mode}/regenerated.html`,
    ]);
    assert.equal(
      readFileSync(`reports/${mode}/regenerated.html`, "utf8"),
      html,
    );
    console.log(
      `${mode}: verified actual data, CLI status, reports, redaction and fixture restoration`,
    );
  } finally {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {}
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {}
    closeSync(fd);
  }
}
