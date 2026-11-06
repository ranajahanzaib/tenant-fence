import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { fileURLToPath } from "node:url";
process.chdir(fileURLToPath(new URL("..", import.meta.url)));
const result = await build({
  entryPoints: ["local/vulnerable.ts"],
  bundle: true,
  write: false,
  format: "esm",
  platform: "browser",
  target: "es2022",
});
const mf = new Miniflare(
  convertV4MiniflareOptions({
    modules: true,
    script: result.outputFiles[0].text,
    compatibilityDate: "2026-10-30",
    host: "127.0.0.1",
    port: 8787,
    d1Databases: { DB: "00000000-0000-0000-0000-000000000001" },
    resourcePersistencePath: ".wrangler/state/v3",
  }),
);
console.log(`LOCAL ONLY vulnerable lab: ${await mf.ready}`);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, async () => {
    await mf.dispose();
    process.exit(0);
  });
