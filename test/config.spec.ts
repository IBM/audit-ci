import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { mapAuditCiConfigToAuditCiFullConfig } from "../lib/config.js";

const directories: string[] = [];
function project(files: Record<string, string> = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-config-"));
  directories.push(directory);
  for (const [name, content] of Object.entries(files))
    writeFileSync(path.join(directory, name), content);
  return directory;
}
afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("programmatic configuration", () => {
  it.each(["package-lock.json", "npm-shrinkwrap.json", "yarn.lock"])("detects %s", (filename) => {
    const directory = project({ [filename]: "{}" });
    expect(
      mapAuditCiConfigToAuditCiFullConfig({ directory, "package-manager": "auto" })[
        "package-manager"
      ],
    ).toBe(filename === "yarn.lock" ? "yarn" : "npm");
  });
  it.each(["yarn@4.18.1", "yarn@4.18.1+sha512.abc", " npm@12.0.0 "])(
    "prefers manifest declaration %s over stale lockfiles",
    (packageManager) => {
      const directory = project({
        "package.json": JSON.stringify({ packageManager }),
        "package-lock.json": "{}",
        "yarn.lock": "",
      });
      expect(mapAuditCiConfigToAuditCiFullConfig({ directory })["package-manager"]).toBe(
        packageManager.trim().startsWith("npm") ? "npm" : "yarn",
      );
    },
  );
  it.each([
    "{ invalid",
    "null",
    "{}",
    '{"packageManager":42}',
    '{"packageManager":"bun@1.0.0"}',
    '{"packageManager":"yarn@"}',
  ])("falls back to lockfiles for manifest %s", (manifest) => {
    const directory = project({ "package.json": manifest, "yarn.lock": "" });
    expect(mapAuditCiConfigToAuditCiFullConfig({ directory })["package-manager"]).toBe("yarn");
  });
  it("preserves existing lockfile priority when no manager is declared", () => {
    const directory = project({ "package-lock.json": "{}", "yarn.lock": "" });
    expect(mapAuditCiConfigToAuditCiFullConfig({ directory })["package-manager"]).toBe("npm");
  });
  it("preserves explicit package manager selection", () => {
    const directory = project({ "package.json": '{"packageManager":"yarn@4.0.0"}' });
    expect(
      mapAuditCiConfigToAuditCiFullConfig({ directory, "package-manager": "npm" })[
        "package-manager"
      ],
    ).toBe("npm");
  });
  it("gives actionable guidance when auto detection fails", () => {
    expect(() => mapAuditCiConfigToAuditCiFullConfig({ directory: project() })).toThrow(
      "Set package.json#packageManager",
    );
  });
  it("preserves executable overrides and programmatic extra arguments", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "npm",
      _npm: "/custom/npm",
      _yarn: "/custom/yarn",
      "extra-args": ["\\--flag", "--foo"],
    });
    expect(config._npm).toBe("/custom/npm");
    expect(config._yarn).toBe("/custom/yarn");
    expect(config["extra-args"]).toEqual(["\\--flag", "--foo"]);
  });
  it("applies defaults", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({ "package-manager": "npm" });
    expect(config.levels).toEqual({ low: false, moderate: false, high: false, critical: false });
    expect(config["report-type"]).toBe("important");
    expect(config.allowlist).toBeInstanceOf(Allowlist);
    expect(config["show-found"]).toBe(true);
    expect(config["show-not-found"]).toBe(true);
  });
});
