import path from "path";
import semver from "semver";
import { afterEach, describe, expect, it as unskippableIt, vi } from "vitest";
import Allowlist from "../lib/allowlist.js";
import audit from "../lib/audit.js";
import {
  config as baseConfig,
  summaryWithDefault,
  testDirectory,
} from "./common.js";

const yarnVersion = "4.2.2";
const yarnAbsolutePath = path.resolve(__dirname, `./yarn-${yarnVersion}.cjs`);

const canRunYarnBerry = semver.gte(process.version, "12.13.0");
const it = canRunYarnBerry ? unskippableIt : unskippableIt.skip;

afterEach(() => {
  vi.restoreAllMocks();
});

const config = (
  additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">,
) =>
  baseConfig({
    ...additions,
    "package-manager": "yarn",
    _yarn: yarnAbsolutePath,
  });

describe(
  "yarn-4-auditor",
  () => {
    it("reports critical severity", async () => {
      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-critical`),
          levels: { critical: true },
          "report-type": "full",
        }),
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

    it("does not report critical if level is set to false", async () => {
      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-critical`),
          levels: { critical: false },
        }),
        (_summary) => _summary,
      );
      expect(summary).to.eql(summaryWithDefault());
    });

    it("reports high severity", async () => {
      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-high`),
          levels: { high: true },
          "report-type": "summary",
        }),
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

    it("does not report high severity if level is set to false", async () => {
      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-high`),
          levels: { high: false },
        }),
        (_summary) => _summary,
      );
      expect(summary).to.eql(summaryWithDefault());
    });

    it("respects the allowlist", async () => {
      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-high`),
          levels: { high: true },
          allowlist: new Allowlist(["GHSA-hrpp-h998-j3pp"]),
        }),
        (_summary) => _summary,
      );
      expect(summary).to.eql(
        summaryWithDefault({
          allowlistedAdvisoriesFound: ["GHSA-hrpp-h998-j3pp"],
        }),
      );
    });

    it("prints a synthesized summary for Yarn 4", async () => {
      const consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {
        return;
      });

      await audit(
        config({
          directory: testDirectory(`yarn-4-high`),
          levels: { high: true },
          "report-type": "summary",
        }),
        (_summary) => _summary,
      );

      const summaryLogs = consoleLogSpy.mock.calls
        .map(([argument]) => argument)
        .filter(
          (argument): argument is string =>
            typeof argument === "string" &&
            argument.includes(`"vulnerabilities"`),
        );

      expect(summaryLogs).to.have.length(1);
      const parsedSummary = JSON.parse(summaryLogs[0]) as {
        vulnerabilities: Record<string, number>;
      };
      expect(parsedSummary.vulnerabilities).to.include({
        info: 0,
        high: 1,
        critical: 0,
      });
      expect(parsedSummary.vulnerabilities.low).to.be.a("number");
      expect(parsedSummary.vulnerabilities.moderate).to.be.a("number");
    });

    it("prints a synthesized summary for Yarn 4 important output", async () => {
      const consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {
        return;
      });

      await audit(
        config({
          directory: testDirectory(`yarn-4-high`),
          "report-type": "important",
        }),
        (_summary) => _summary,
      );

      const jsonLogs = consoleLogSpy.mock.calls
        .map(([argument]) => argument)
        .filter(
          (argument): argument is string =>
            typeof argument === "string" && argument.trim().startsWith("{"),
        );
      const summaryLogs = jsonLogs.filter((argument) =>
        argument.includes(`"vulnerabilities"`),
      );

      expect(jsonLogs).to.have.length(1);
      expect(summaryLogs).to.have.length(1);
      const parsedSummary = JSON.parse(summaryLogs[0]) as {
        vulnerabilities: Record<string, number>;
      };
      expect(parsedSummary.vulnerabilities).to.include({
        info: 0,
        high: 1,
        critical: 0,
      });
      expect(parsedSummary.vulnerabilities.low).to.be.a("number");
      expect(parsedSummary.vulnerabilities.moderate).to.be.a("number");
    });

    it("filters Yarn 4 deprecation-only lines from important output", async () => {
      const consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {
        return;
      });

      await audit(
        config({
          directory: testDirectory(`yarn-4-deprecation-summary`),
          levels: { moderate: true },
          "report-type": "important",
        }),
        (_summary) => _summary,
      );

      const jsonLogs = consoleLogSpy.mock.calls
        .map(([argument]) => argument)
        .filter((argument): argument is string => typeof argument === "string");

      expect(jsonLogs.some((line) => line.includes("inflight"))).to.equal(false);
      expect(jsonLogs.some((line) => line.includes(`"value": "open"`))).to.equal(
        true,
      );
    });

    it("ignores deprecation findings in a synthesized Yarn 4 summary", async () => {
      const consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {
        return;
      });

      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-deprecation-summary`),
          levels: { moderate: true },
          "report-type": "summary",
        }),
        (_summary) => _summary,
      );

      const summaryLogs = consoleLogSpy.mock.calls
        .map(([argument]) => argument)
        .filter(
          (argument): argument is string =>
            typeof argument === "string" &&
            argument.includes(`"vulnerabilities"`),
        );

      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["critical"],
          advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
          advisoryPathsFound: ["GHSA-28xh-wpgr-7fm8|open"],
        }),
      );
      expect(summaryLogs).to.have.length(1);
      expect(JSON.parse(summaryLogs[0])).to.eql({
        vulnerabilities: {
          info: 0,
          low: 0,
          moderate: 0,
          high: 0,
          critical: 1,
        },
      });
    });

    it("supports Yarn 4 path allowlists based on dependents", async () => {
      const summary = await audit(
        config({
          directory: testDirectory(`yarn-4-workspace`),
          levels: { high: true },
          allowlist: new Allowlist([
            "GHSA-hrpp-h998-j3pp|audit-ci-yarn-4-workspace-high-vulnerability>qs",
          ]),
        }),
        (_summary) => _summary,
      );

      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["critical"],
          advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
          allowlistedPathsFound: [
            "GHSA-hrpp-h998-j3pp|audit-ci-yarn-4-workspace-high-vulnerability>qs",
          ],
          advisoryPathsFound: [
            "GHSA-28xh-wpgr-7fm8|audit-ci-yarn-4-workspace-critical-vulnerability-dev>open",
          ],
        }),
      );
    });
  },
  { timeout: 30_000 },
);
