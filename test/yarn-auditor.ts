import semver, { SemVer } from "semver";
import { describe, expect, it as unskippableIt } from "vitest";
import Allowlist from "../lib/allowlist.js";
import audit from "../lib/audit.js";
import {
  config as baseConfig,
  summaryWithDefault,
  testDirectory,
} from "./common.js";

const nodeVersion = process.version;

const canRunYarnBerry = semver.gte(nodeVersion, "12.13.0");

export interface PerformAuditTests {
  yarnAbsolutePath: string;
  yarnVersion: SemVer;
}

export function performAuditTests({
  yarnAbsolutePath,
  yarnVersion,
}: PerformAuditTests) {
  const { major: majorVersion } = yarnVersion;

  const config = (
    additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">,
  ) =>
    baseConfig({
      ...additions,
      "package-manager": "yarn",
      _yarn: yarnAbsolutePath,
    });

  const it =
    !canRunYarnBerry && majorVersion > 1 ? unskippableIt.skip : unskippableIt;

  // To modify what slow times are, need to use
  // function() {} instead of () => {}
  describe(
    `yarn-${majorVersion}-auditor`,
    function testYarnAuditor() {
      it("prints full report with critical severity", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-critical`),
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
      it("does not report critical severity if it set to false", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-critical`),
            levels: { critical: false },
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(summaryWithDefault());
      });
      it("reports summary with high severity", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-high`),
            levels: { high: true },
            "report-type": "summary",
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            failedLevelsFound: ["high"],
            advisoriesFound: ["GHSA-38f5-ghc2-fcmv"],
            advisoryPathsFound: ["GHSA-38f5-ghc2-fcmv|cryo"],
          }),
        );
      });
      it("reports important info with moderate severity", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            allowlist: new Allowlist([
              "GHSA-9wf9-qvvp-2929",
              "GHSA-hm7f-rq7q-j9xp",
            ]),
            levels: { moderate: true },
            "report-type": "important",
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            failedLevelsFound: ["moderate"],
            allowlistedAdvisoriesFound: [
              "GHSA-9wf9-qvvp-2929",
              "GHSA-hm7f-rq7q-j9xp",
            ],
            advisoriesFound: ["GHSA-9wf9-qvvp-2929", "GHSA-rvg8-pwq2-xj7q"],
            advisoryPathsFound: [
              "GHSA-9wf9-qvvp-2929|@builder.io/qwik",
              "GHSA-rvg8-pwq2-xj7q|base64url",
            ],
          }),
        );
      });
      it("does not report moderate severity if it set to false", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: false },
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(summaryWithDefault());
      });
      it("ignores an advisory if it is allowlisted", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: true },
            allowlist: new Allowlist([
              "GHSA-9wf9-qvvp-2929",
              "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
              "GHSA-rvg8-pwq2-xj7q",
            ]),
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
            allowlistedPathsFound: ["GHSA-hm7f-rq7q-j9xp|@builder.io/qwik"],
          }),
        );
      });
      it("ignores an advisory if it is allowlisted using a NSPRecord", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: true },
            allowlist: new Allowlist([
              {
                "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik": {
                  active: true,
                },
              },
              {
                "GHSA-rvg8-pwq2-xj7q": {
                  active: true,
                },
              },
            ]),
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
            allowlistedPathsFound: ["GHSA-hm7f-rq7q-j9xp|@builder.io/qwik"],
          }),
        );
      });
      it("does not ignore an advisory that is not allowlisted", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: true },
            allowlist: new Allowlist(["GHSA-cff4-rrq6-h78w"]),
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
            failedLevelsFound: ["moderate"],
            advisoriesFound: ["GHSA-hm7f-rq7q-j9xp", "GHSA-rvg8-pwq2-xj7q"],
            advisoryPathsFound: [
              "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
              "GHSA-rvg8-pwq2-xj7q|base64url",
            ],
          }),
        );
      });
      it("does not ignore an advisory that is not allowlisted using a NSPRecord", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: true },
            allowlist: new Allowlist([
              "GHSA-cff4-rrq6-h78w",
              {
                "GHSA-rvg8-pwq2-xj7q": {
                  active: false,
                },
              },
            ]),
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
            failedLevelsFound: ["moderate"],
            advisoriesFound: ["GHSA-hm7f-rq7q-j9xp", "GHSA-rvg8-pwq2-xj7q"],
            advisoryPathsFound: [
              "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
              "GHSA-rvg8-pwq2-xj7q|base64url",
            ],
          }),
        );
      });
      it("ignores an advisory that has not expired", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: true },
            allowlist: new Allowlist([
              {
                "GHSA-rvg8-pwq2-xj7q": {
                  active: true,
                  expiry: new Date(Date.now() + 9000).toISOString(),
                },
              },
              {
                "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik": {
                  active: true,
                  expiry: new Date(Date.now() + 9000).toISOString(),
                },
              },
            ]),
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
            allowlistedPathsFound: ["GHSA-hm7f-rq7q-j9xp|@builder.io/qwik"],
          }),
        );
      });
      it("does not ignore an advisory that has expired", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-moderate`),
            levels: { moderate: true },
            allowlist: new Allowlist([
              "GHSA-cff4-rrq6-h78w",
              {
                "GHSA-rvg8-pwq2-xj7q": {
                  active: true,
                  expiry: new Date(Date.now() - 9000).toISOString(),
                },
              },
              {
                "*|@builder.io/qwik": {
                  active: true,
                  expiry: new Date(Date.now() - 9000).toISOString(),
                },
              },
            ]),
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(
          summaryWithDefault({
            allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
            failedLevelsFound: ["moderate"],
            advisoriesFound: ["GHSA-hm7f-rq7q-j9xp", "GHSA-rvg8-pwq2-xj7q"],
            advisoryPathsFound: [
              "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
              "GHSA-rvg8-pwq2-xj7q|base64url",
            ],
          }),
        );
      });
      it("reports low severity", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-low`),
            levels: { low: true },
          }),
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
      it("passes with no vulnerabilities", async () => {
        const summary = await audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-none`),
            levels: { low: true },
          }),
          (_summary) => _summary,
        );
        expect(summary).to.eql(summaryWithDefault());
      });
      it("doesn't use the registry flag since it's not supported in Yarn yet", () =>
        audit(
          config({
            directory: testDirectory(`yarn-${majorVersion}-low`),
            levels: { low: true },
            registry: "https://example.com",
          }),
          (_summary) => _summary,
        ));
    },
    {
      timeout: 10_000,
    },
  );
}
