import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { mapAuditCiConfigToAuditCiFullConfig } from "../lib/config.js";
import { testDirectory } from "./common.js";

describe("mapAuditCiConfigToAuditCiFullConfig", () => {
  it("resolves auto package manager from package-lock.json", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory: testDirectory("npm-critical"),
    });
    expect(config["package-manager"]).toBe("npm");
  });

  it("resolves auto package manager from npm-shrinkwrap.json", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-shrinkwrap-"));
    writeFileSync(path.join(directory, "npm-shrinkwrap.json"), "{}");
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory,
    });
    expect(config["package-manager"]).toBe("npm");
  });

  it("resolves auto package manager from yarn.lock", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory: testDirectory("yarn-1-critical"),
    });
    expect(config["package-manager"]).toBe("yarn");
  });

  it("resolves auto package manager from pnpm-lock.yaml", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory: testDirectory("pnpm-critical"),
    });
    expect(config["package-manager"]).toBe("pnpm");
  });

  it("throws when auto cannot detect a package manager", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-empty-"));
    expect(() =>
      mapAuditCiConfigToAuditCiFullConfig({
        "package-manager": "auto",
        directory,
      }),
    ).toThrow("Cannot establish package-manager type.");
  });

  it("ignores invalid package.json#packageManager values", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-invalid-package-manager-"));
    writeFileSync(
      path.join(directory, "package.json"),
      JSON.stringify({ packageManager: "node@20.0.0" }),
    );
    writeFileSync(path.join(directory, "pnpm-lock.yaml"), "lockfileVersion: 6\n");

    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory,
    });
    expect(config["package-manager"]).toBe("pnpm");
  });

  it("ignores malformed package.json files", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-malformed-package-json-"));
    writeFileSync(path.join(directory, "package.json"), "{ not-json");
    writeFileSync(path.join(directory, "yarn.lock"), "# yarn lockfile v1\n");

    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory,
    });
    expect(config["package-manager"]).toBe("yarn");
  });

  it("resolves auto package manager from package.json#packageManager", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-package-manager-field-"));
    writeFileSync(
      path.join(directory, "package.json"),
      JSON.stringify({ packageManager: "pnpm@9.0.0" }),
    );
    writeFileSync(path.join(directory, "package-lock.json"), "{}");

    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory,
    });
    expect(config["package-manager"]).toBe("pnpm");
  });

  it("resolves auto package manager from package.json#packageManager with a Corepack hash", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-package-manager-hash-"));
    writeFileSync(
      path.join(directory, "package.json"),
      JSON.stringify({
        packageManager:
          "pnpm@11.1.2+sha512.415a1cc25974731e75455c1468371be74c5aa5fb7621b50d4056d222451609f11412f23fd602e6169f1e060466641f798597e1be961a10688836a67b16569499",
      }),
    );

    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory,
    });
    expect(config["package-manager"]).toBe("pnpm");
  });

  it("prefers yarn.lock over package-lock.json when packageManager is not set", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "audit-ci-conflicting-locks-"));
    writeFileSync(path.join(directory, "package.json"), JSON.stringify({ name: "example" }));
    writeFileSync(path.join(directory, "package-lock.json"), "{}");
    writeFileSync(path.join(directory, "yarn.lock"), "# yarn lockfile v1\n");

    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "auto",
      directory,
    });
    expect(config["package-manager"]).toBe("yarn");
  });

  it("preserves explicit package manager selection", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "pnpm",
      directory: testDirectory("npm-critical"),
    });
    expect(config["package-manager"]).toBe("pnpm");
  });

  it("passes through extra-args unchanged", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "npm",
      "extra-args": ["\\--legacy-peer-deps", "--foo"],
    });
    expect(config["extra-args"]).toEqual(["\\--legacy-peer-deps", "--foo"]);
  });

  it("preserves internal package manager executables", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "yarn",
      _yarn: "/custom/yarn",
      _npm: "/custom/npm",
      _pnpm: "/custom/pnpm",
    });
    expect(config._yarn).toBe("/custom/yarn");
    expect(config._npm).toBe("/custom/npm");
    expect(config._pnpm).toBe("/custom/pnpm");
  });

  it("applies defaults for optional fields", () => {
    const config = mapAuditCiConfigToAuditCiFullConfig({
      "package-manager": "npm",
    });
    expect(config.levels).toEqual({
      low: false,
      moderate: false,
      high: false,
      critical: false,
    });
    expect(config["report-type"]).toBe("important");
    expect(config.allowlist).toBeInstanceOf(Allowlist);
    expect(config["show-not-found"]).toBe(true);
    expect(config["show-found"]).toBe(true);
  });
});
