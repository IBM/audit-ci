import { readFileSync } from "node:fs";
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
  it.each([
    ["tool@workspace:packages/tool", "tool>glob"],
    ["@scope/tool@workspace:packages/tool", "@scope/tool>glob"],
    ["@scope/tool@virtual:abc#npm:1.0.0", "@scope/tool>glob"],
    ["tool@patch:tool@npm:1.0.0#./patch", "tool>glob"],
    ["tool", "tool>glob"],
    ["project@workspace:.", "glob"],
  ])("maps Yarn locator %s to %s", async (dependent, expectedPath) => {
    wire.lines = [
      { ...advisory, children: { ...advisory.children, Dependents: [dependent, dependent] } },
    ];
    expect((await audit()).advisoryPathsFound).to.eql([`GHSA-3g3m-2fjr-6pw4|${expectedPath}`]);
  });

  it("preserves workspace path allowlists in the captured Yarn 4 fixture", async () => {
    wire.lines = readFileSync(new URL("./yarn-4-workspace/output.json", import.meta.url), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const allowedPath = "GHSA-hrpp-h998-j3pp|audit-ci-yarn-4-workspace-high-vulnerability>qs";
    expect(
      await audit({
        levels: { low: false, moderate: false, high: true, critical: true },
        allowlist: new Allowlist([allowedPath]),
      }),
    ).to.eql(
      summaryWithDefault({
        advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
        failedLevelsFound: ["critical"],
        allowlistedPathsFound: [allowedPath],
        advisoryPathsFound: [
          "GHSA-28xh-wpgr-7fm8|audit-ci-yarn-4-workspace-critical-vulnerability-dev>open",
        ],
      }),
    );
  });

  it.each(["summary", "important", "full"] as const)(
    "excludes deprecations from %s vulnerability counts",
    async (reportType) => {
      const deprecation = {
        ...advisory,
        children: { ...advisory.children, ID: "glob (deprecation)", URL: undefined },
      };
      wire.lines = [deprecation, advisory];
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      expect((await audit({ "report-type": reportType })).advisoriesFound).to.eql([
        "GHSA-3g3m-2fjr-6pw4",
      ]);
      const jsonLogs = log.mock.calls
        .map(([line]) => line)
        .filter((line): line is string => typeof line === "string" && line.startsWith("{"));
      const deprecations = jsonLogs.filter((line) => line.includes("(deprecation)"));
      expect(deprecations).toHaveLength(reportType === "full" ? 1 : 0);
      if (reportType !== "full") {
        expect(
          jsonLogs
            .filter((line) => line.includes('"vulnerabilities"'))
            .map((line) => JSON.parse(line)),
        ).to.eql([{ vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0 } }]);
      }
    },
  );

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
  it("keeps distinct advisories with string IDs", async () => {
    wire.lines = [
      advisory,
      {
        ...advisory,
        value: "other",
        children: {
          ...advisory.children,
          ID: "another-id",
          URL: "https://github.com/advisories/GHSA-rvg8-pwq2-xj7q",
        },
      },
    ];
    expect((await audit()).advisoriesFound).to.eql(["GHSA-3g3m-2fjr-6pw4", "GHSA-rvg8-pwq2-xj7q"]);
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
  it.each(["summary", "important"] as const)("prints Yarn 4 %s counts", async (reportType) => {
    wire.lines = [advisory];
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await audit({ "report-type": reportType });
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
      { ...advisory, children: { ...advisory.children, ID: "unknown", URL: undefined } },
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
