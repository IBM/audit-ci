import semver, { SemVer } from "semver";
import { describe, expect, it as unskippableIt, vi } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { yellow } from "../lib/colors.js";
import * as common from "../lib/common.js";
import { auditWithFullConfig, reportBerry, reportClassic } from "../lib/yarn-auditor.js";
import { yarnAuditSupportsRegistry } from "../lib/yarn-version.js";
import {
  config as baseConfig,
  readYarnBerryAuditOutput,
  readYarnClassicAuditOutput,
  summaryWithDefault,
  testDirectory,
} from "./common.js";

const nodeVersion = process.version;

const canRunYarnBerry = semver.gte(nodeVersion, "12.13.0");

export interface PerformAuditTests {
  yarnAbsolutePath: string;
  yarnVersion: SemVer;
}

export function performAuditTests({ yarnAbsolutePath, yarnVersion }: PerformAuditTests) {
  const { major: majorVersion } = yarnVersion;
  const isYarnClassic = majorVersion === 1;

  const config = (additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">) =>
    baseConfig({
      ...additions,
      "package-manager": "yarn",
      _yarn: yarnAbsolutePath,
    });

  const yarnFixtureDirectory = (name: string) => `yarn-${majorVersion}-${name}`;

  const reportYarn = (
    name: string,
    additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">,
    reporter: (
      summary: ReturnType<typeof summaryWithDefault>,
    ) => ReturnType<typeof summaryWithDefault>,
  ) => {
    const directory = yarnFixtureDirectory(name);
    const auditConfig = config({ ...additions, directory: testDirectory(directory) });
    if (isYarnClassic) {
      return reportClassic(readYarnClassicAuditOutput(directory), auditConfig, reporter);
    }
    return reportBerry(readYarnBerryAuditOutput(directory), auditConfig, reporter);
  };

  const it = !canRunYarnBerry && majorVersion > 1 ? unskippableIt.skip : unskippableIt;

  // To modify what slow times are, need to use
  // function() {} instead of () => {}
  describe(`yarn-${majorVersion}-auditor`, { timeout: 10_000 }, function testYarnAuditor() {
    it("prints full report with critical severity", () => {
      const summary = reportYarn(
        "critical",
        {
          levels: { critical: true },
          "report-type": "full",
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["critical"],
          advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
          advisoryPathsFound: ["GHSA-28xh-wpgr-7fm8|open"],
        }),
      );
    });
    it("does not report critical severity if it set to false", () => {
      const summary = reportYarn(
        "critical",
        {
          levels: { critical: false },
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(summaryWithDefault());
    });
    it("reports summary with high severity", () => {
      const summary = reportYarn(
        "high",
        {
          levels: { high: true },
          "report-type": "summary",
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["high"],
          advisoriesFound: ["GHSA-hrpp-h998-j3pp"],
          advisoryPathsFound: ["GHSA-hrpp-h998-j3pp|qs"],
        }),
      );
    });
    it("reports important info with moderate severity", () => {
      const summary = reportYarn(
        "moderate",
        {
          allowlist: new Allowlist([]),
          levels: { moderate: true },
          "report-type": "important",
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["moderate"],
          allowlistedAdvisoriesFound: [],
          advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
          advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
        }),
      );
    });
    it("does not report moderate severity if it set to false", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: false },
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(summaryWithDefault());
    });
    it("ignores an advisory if it is allowlisted", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: true },
          allowlist: new Allowlist(["GHSA-rvg8-pwq2-xj7q"]),
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        }),
      );
    });
    it("ignores an advisory if it is allowlisted using a NSPRecord", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: true },
          allowlist: new Allowlist([{ "GHSA-rvg8-pwq2-xj7q": { active: true } }]),
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        }),
      );
    });
    it("does not ignore an advisory that is not allowlisted", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: true },
          allowlist: new Allowlist(["GHSA-cff4-rrq6-h78w"]),
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
          failedLevelsFound: ["moderate"],
          advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
          advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
        }),
      );
    });
    it("does not ignore an advisory that is not allowlisted using a NSPRecord", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: true },
          allowlist: new Allowlist([
            "GHSA-cff4-rrq6-h78w",
            { "GHSA-rvg8-pwq2-xj7q": { active: false } },
          ]),
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
          failedLevelsFound: ["moderate"],
          advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
          advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
        }),
      );
    });
    it("ignores an advisory that has not expired", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: true },
          allowlist: new Allowlist([
            {
              "GHSA-rvg8-pwq2-xj7q|base64url": {
                active: true,
                expiry: new Date(Date.now() + 9000).toISOString(),
              },
            },
          ]),
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
        }),
      );
    });
    it("does not ignore an advisory that has expired", () => {
      const summary = reportYarn(
        "moderate",
        {
          levels: { moderate: true },
          allowlist: new Allowlist([
            "GHSA-cff4-rrq6-h78w",
            {
              "GHSA-rvg8-pwq2-xj7q": {
                active: true,
                expiry: new Date(Date.now() - 9000).toISOString(),
              },
            },
          ]),
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
          failedLevelsFound: ["moderate"],
          advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
          advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
        }),
      );
    });
    it("reports low severity", () => {
      const summary = reportYarn(
        "low",
        {
          levels: { low: true },
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["low"],
          advisoriesFound: ["GHSA-c6rq-rjc2-86v2"],
          advisoryPathsFound: ["GHSA-c6rq-rjc2-86v2|chownr"],
        }),
      );
    });
    it("passes with no vulnerabilities", () => {
      const summary = reportYarn(
        "none",
        {
          levels: { low: true },
        },
        (_summary) => _summary,
      );
      expect(summary).to.eql(summaryWithDefault());
    });
    it("doesn't use the registry flag since it's not supported in Yarn yet", async () => {
      expect(yarnAuditSupportsRegistry(yarnVersion)).toBe(false);
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const runProgramSpy = vi.spyOn(common, "runProgram").mockResolvedValue();
      try {
        await auditWithFullConfig(
          config({
            directory: testDirectory(yarnFixtureDirectory("low")),
            levels: { low: true },
            registry: "https://example.com",
          }),
          (_summary) => _summary,
        );
        expect(warnSpy).toHaveBeenCalledWith(
          yellow,
          "Yarn audit does not support the registry flag yet.",
        );
        const arguments_ = runProgramSpy.mock.calls[0]?.[1] as string[] | undefined;
        expect(arguments_).toBeDefined();
        expect(arguments_).not.toContain("--registry");
        expect(arguments_).not.toContain("https://example.com");
      } finally {
        warnSpy.mockRestore();
        runProgramSpy.mockRestore();
      }
    });
  });
}
