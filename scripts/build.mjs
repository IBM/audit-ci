import { spawnSync } from "node:child_process";
import { chmodSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
rmSync(new URL("dist/", root), { recursive: true, force: true });
const compiler = fileURLToPath(new URL("node_modules/typescript/bin/tsc", root));
const result = spawnSync(process.execPath, [compiler, "-p", "tsconfig.build.json"], {
  cwd: root,
  stdio: "inherit",
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
chmodSync(new URL("dist/bin.js", root), 0o755);
