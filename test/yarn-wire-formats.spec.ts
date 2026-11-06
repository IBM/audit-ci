import type { YarnNpmAuditReport } from "audit-types";
import { afterEach, describe, expect, it, vi } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { auditWithFullConfig } from "../lib/yarn-auditor.js";
import { config, summaryWithDefault } from "./common.js";

const wire = vi.hoisted(() => ({ version: "4.18.1", lines: [] as unknown[] }));
vi.mock("../lib/yarn-version.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/yarn-version.js")>()),
  getYarnVersion: () => wire.version,
}));
vi.mock("../lib/common.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/common.js")>()),
  runProgram: async (
    _exe: string,
    _args: string[],
    _options: unknown,
    out: (line: unknown) => void,
  ) => {
    for (const line of wire.lines) out(line);
  },
}));

const advisory = {
  value: "glob",
  children: {
    ID: "1244013",
    Issue: "AbortSignal cancellation bypass",
    URL: "https://github.com/advisories/GHSA-3g3m-2fjr-6pw4",
    Severity: "moderate",
    "Vulnerable Versions": "<=14.0.1",
    "Tree Versions": ["14.0.1"],
    Dependents: ["project@workspace:."],
  },
} satisfies YarnNpmAuditReport.AuditAdvisory;

function audit(options: Partial<ReturnType<typeof config>> = {}) {
  return auditWithFullConfig(
    config({
      "package-manager": "yarn",
      levels: { moderate: true },
      ...options,
    }),
    (summary) => summary,
  );
}

afterEach(() => {
  wire.version = "4.18.1";
  wire.lines = [];
  vi.restoreAllMocks();
});

describe("Yarn wire formats", () => {
  it("processes Yarn 4 advisory trees and string IDs", async () => {
    wire.lines = [advisory];
    expect(await audit()).to.eql(
      summaryWithDefault({
        advisoriesFound: ["GHSA-3g3m-2fjr-6pw4"],
        failedLevelsFound: ["moderate"],
        advisoryPathsFound: ["GHSA-3g3m-2fjr-6pw4|glob"],
      }),
    );
  });
  it("preserves scoped dependent names and supports path allowlisting", async () => {
    wire.lines = [
      { ...advisory, children: { ...advisory.children, Dependents: ["@scope/tool@2.0.0"] } },
    ];
    const path = "GHSA-3g3m-2fjr-6pw4|@scope/tool>glob";
    expect(await audit({ allowlist: new Allowlist([path]) })).to.eql(
      summaryWithDefault({ allowlistedPathsFound: [path] }),
    );
  });
  it("accepts empty Yarn 4 output and informational diagnostics", async () => {
    expect(await audit()).to.eql(summaryWithDefault());
    wire.lines = [
      {
        type: "info",
        name: null,
        displayName: "YN0000",
        indent: "",
        data: "Done",
      } satisfies YarnNpmAuditReport.Message,
    ];
    expect(await audit()).to.eql(summaryWithDefault());
  });
  it("prints Yarn 4 summary counts", async () => {
    wire.lines = [advisory];
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await audit({ "report-type": "summary" });
    expect(log).toHaveBeenCalledWith(
      JSON.stringify(
        { vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0 } },
        undefined,
        2,
      ),
    );
  });
  it("rejects unidentified Yarn 4 advisories unless their module is allowlisted", async () => {
    wire.lines = [
      { ...advisory, children: { ...advisory.children, ID: "glob (deprecation)", URL: undefined } },
    ];
    await expect(audit()).rejects.toThrow("missing URL");
    expect(await audit({ allowlist: new Allowlist(["glob"]) })).to.eql(
      summaryWithDefault({ allowlistedModulesFound: ["glob"] }),
    );
  });
  it.each(["2.4.0", "4.18.1"])("rejects audit errors on Yarn %s", async (version) => {
    wire.version = version;
    wire.lines = version.startsWith("2")
      ? [{ error: { summary: "Registry failed", detail: "" } }]
      : [{ type: "error", data: "Registry failed" }];
    await expect(audit()).rejects.toThrow("Registry failed");
  });
  it("prints Yarn Classic summary metadata", async () => {
    wire.version = "1.22.22";
    const metadata = {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
      dependencies: 1,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: 1,
    };
    wire.lines = [{ type: "auditSummary", data: metadata }];
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await audit({ "report-type": "summary" });
    expect(log).toHaveBeenCalledWith(JSON.stringify(metadata, undefined, 2));
  });
});
