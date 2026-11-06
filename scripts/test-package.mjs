import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const temporary = mkdtempSync(path.join(tmpdir(), "audit-ci-package-"));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run this check with npm run test:package");

function run(command, args, cwd, expectedStatus = 0, env = process.env) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", env });
  if (result.error) throw result.error;
  assert.equal(
    result.status,
    expectedStatus,
    `${command} ${args.join(" ")}\n${result.stdout}\n${result.stderr}`,
  );
  return result.stdout;
}
function npm(args, cwd) {
  return run(process.execPath, [npmCli, ...args], cwd);
}

try {
  const [packed] = JSON.parse(npm(["pack", "--json", "--pack-destination", temporary], root));
  const files = packed.files.map(({ path: filename }) => filename);
  for (const required of [
    "dist/bin.js",
    "dist/index.js",
    "dist/index.d.ts",
    "dist/model.d.ts",
    "dist/config.js",
  ]) {
    assert.ok(files.includes(required), `Package is missing ${required}`);
  }
  assert.ok(!files.some((filename) => /\.(?:cjs|cts)$/.test(filename)), "Package must be ESM-only");
  assert.ok(
    !files.some((filename) => /^(?:lib|test|scripts)\//.test(filename)),
    "Package contains development sources",
  );

  const consumer = path.join(temporary, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    path.join(consumer, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  npm(
    [
      "install",
      "--omit=dev",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      path.join(temporary, packed.filename),
    ],
    consumer,
  );

  const esm =
    'import { Allowlist, npmAudit, mapVulnerabilityLevelInput } from "audit-ci";\nimport assert from "node:assert/strict";\nassert.equal(typeof npmAudit, "function");\nassert.deepEqual(new Allowlist(["example"]).modules, ["example"]);\nassert.equal(mapVulnerabilityLevelInput({ moderate: true }).critical, true);\n';
  writeFileSync(path.join(consumer, "consumer.mjs"), esm);
  run(process.execPath, ["consumer.mjs"], consumer);
  writeFileSync(
    path.join(consumer, "consumer.cjs"),
    'const assert = require("node:assert/strict");\n(async () => { const { Allowlist, npmAudit } = await import("audit-ci"); assert.equal(typeof npmAudit, "function"); assert.deepEqual(new Allowlist().modules, []); })().catch(error => { console.error(error); process.exitCode = 1; });\n',
  );
  run(process.execPath, ["consumer.cjs"], consumer);

  writeFileSync(
    path.join(consumer, "consumer.mts"),
    'import { npmAudit, type AuditCiConfig, type Summary } from "audit-ci";\nconst config: AuditCiConfig = { "package-manager": "auto", moderate: true };\nconst result: Promise<Summary> = npmAudit(config);\nvoid result;\n// @ts-expect-error severity flags require booleans\nconst invalid: AuditCiConfig = { moderate: "yes" };\nvoid invalid;\n',
  );
  writeFileSync(
    path.join(consumer, "consumer.cts"),
    'async function check() { const { npmAudit } = await import("audit-ci"); return npmAudit({ moderate: true }); }\nvoid check;\n',
  );
  run(
    process.execPath,
    [
      path.join(root, "node_modules/typescript/bin/tsc"),
      "--noEmit",
      "--strict",
      "--module",
      "NodeNext",
      "--target",
      "ES2023",
      "consumer.mts",
      "consumer.cts",
    ],
    consumer,
  );

  const cli = path.join(consumer, "node_modules/audit-ci/dist/bin.js");
  assert.equal(run(process.execPath, [cli, "--version"], consumer).trim(), manifest.version);
  assert.match(run(process.execPath, [cli, "--help"], consumer), /--package-manager/);
  if (process.platform !== "win32") {
    assert.match(
      run(path.join(consumer, "node_modules/.bin/audit-ci"), ["--help"], consumer),
      /--package-manager/,
    );
  }

  const fixture = JSON.parse(
    readFileSync(path.join(root, "test/npm-moderate/npm7-output.json"), "utf8"),
  );
  const mockBin = path.join(consumer, "mock-bin");
  mkdirSync(mockBin);
  const mockNpm = path.join(mockBin, "npm");
  writeFileSync(
    mockNpm,
    `#!/usr/bin/env node\nconsole.log(${JSON.stringify(JSON.stringify(fixture))});\nprocess.exitCode = 1;\n`,
  );
  chmodSync(mockNpm, 0o755);
  writeFileSync(path.join(mockBin, "npm.cmd"), `@"${process.execPath}" "${mockNpm}" %*\r\n`);
  const env = { ...process.env, PATH: `${mockBin}${path.delimiter}${process.env.PATH ?? ""}` };
  const args = [cli, "--package-manager", "npm", "--moderate"];
  assert.match(run(process.execPath, args, consumer, 1, env), /NPM audit report results/);
  assert.match(
    run(process.execPath, [...args, "--allowlist", "GHSA-rvg8-pwq2-xj7q"], consumer, 0, env),
    /Passed npm security audit/,
  );
  writeFileSync(
    path.join(consumer, "audit-ci.jsonc"),
    '{\n// Packed CLI config test\n"package-manager": "npm", "moderate": true, "allowlist": ["GHSA-rvg8-pwq2-xj7q"]\n}\n',
  );
  assert.match(
    run(process.execPath, [cli, "--config", "audit-ci.jsonc"], consumer, 0, env),
    /Passed npm security audit/,
  );
  writeFileSync(
    path.join(consumer, "api.mjs"),
    `import assert from "node:assert/strict";\nimport { npmAudit } from "audit-ci";\nconst summary = await npmAudit({ "package-manager": "npm", moderate: true, _npm: ${JSON.stringify(process.platform === "win32" ? `${mockNpm}.cmd` : mockNpm)}, allowlist: ["GHSA-rvg8-pwq2-xj7q"] });\nassert.deepEqual(summary.failedLevelsFound, []);\n`,
  );
  run(process.execPath, ["api.mjs"], consumer, 0, env);
  console.log(
    `Verified audit-ci@${manifest.version}: packed files, ESM, CommonJS dynamic import, declarations, and CLI.`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
