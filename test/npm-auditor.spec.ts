import { NPMAuditReportV1 } from "audit-types";
import { describe, expect, it } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { auditWithFullConfig, report } from "../lib/npm-auditor.js";
import {
  config as baseConfig,
  summaryWithDefault,
  testDirectory,
} from "./common.js";

import untypedReportNpmAllowlistedPath from "./npm-allowlisted-path/npm-output.json";
import untypedReportNpmCritical from "./npm-critical/npm-output.json";
import untypedReportNpmHighSeverity from "./npm-high/npm-output.json";
import untypedReportNpmLow from "./npm-low/npm-output.json";
import untypedReportNpmModerateSeverity from "./npm-moderate/npm-output.json";
import untypedReportNpmNone from "./npm-none/npm-output.json";
import untypedReportNpmSkipDevelopment from "./npm-skip-dev/npm-output.json";

const reportNpmAllowlistedPath =
  untypedReportNpmAllowlistedPath as NPMAuditReportV1.Audit;
const reportNpmCritical = untypedReportNpmCritical as NPMAuditReportV1.Audit;
const reportNpmHighSeverity =
  untypedReportNpmHighSeverity as NPMAuditReportV1.Audit;
const reportNpmLow = untypedReportNpmLow as NPMAuditReportV1.Audit;
const reportNpmModerateSeverity =
  untypedReportNpmModerateSeverity as NPMAuditReportV1.Audit;
const reportNpmNone = untypedReportNpmNone as NPMAuditReportV1.Audit;
const reportNpmSkipDevelopment =
  untypedReportNpmSkipDevelopment as NPMAuditReportV1.Audit;

function config(
  additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">,
) {
  return baseConfig({ ...additions, "package-manager": "npm" });
}

// To modify what slow times are, need to use
// function() {} instead of () => {}
describe("npm-auditor", () => {
  it("prints full report with critical severity", () => {
    const summary = report(
      reportNpmCritical,
      config({
        directory: testDirectory("npm-critical"),
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
  it("does not report critical severity if it set to false", () => {
    const summary = report(
      reportNpmCritical,
      config({
        directory: testDirectory("npm-critical"),
        levels: { critical: false },
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with high severity", () => {
    const summary = report(
      reportNpmHighSeverity,
      config({
        directory: testDirectory("npm-high"),
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
  it("reports important info with moderate severity", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      }),
    );
  });
  it("does not report moderate severity if it set to false", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: false },
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("ignores an advisory if it is allowlisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist(["GHSA-rvg8-pwq2-xj7q"]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
      }),
    );
  });
  it("ignores an advisory if it is allowlisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist(["GHSA-rvg8-pwq2-xj7q"]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
      }),
    );
  });
  it("ignores an advisory if it is allowlisted using a NSPRecord", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([
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
      }),
    );
  });
  it("does not ignore an advisory that is not allowlisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist(["GHSA-cff4-rrq6-h78w"]),
      }),
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
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
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
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      }),
    );
  });
  it("ignores an advisory that has not expired", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          {
            "GHSA-rvg8-pwq2-xj7q": {
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
      }),
    );
  });
  it("does not ignore an advisory that has expired", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
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
      }),
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
  it("reports only vulnerabilities with a not allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDirectory("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "*|github-build>axios",
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>*",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
        ]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        advisoriesFound: [
          "GHSA-4w2v-q235-vp99",
          "GHSA-74fj-2j2h-c42q",
          "GHSA-cph5-m8f7-6c5x",
        ],
        failedLevelsFound: ["high"],
        allowlistedPathsFound: [
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
        ],
        advisoryPathsFound: [
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
        ],
      }),
    );
  });
  it("allowlist all vulnerabilities with an allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDirectory("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
        ]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
        ],
      }),
    );
  });
  it("allowlist all vulnerabilities matching a wildcard allowlist path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDirectory("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["*|axios", "*|axios>*", "*|github-build>*"]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
        ],
      }),
    );
  });
  it("reports low severity", () => {
    const summary = report(
      reportNpmLow,
      config({
        directory: testDirectory("npm-low"),
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
  it("passes with no vulnerabilities", () => {
    const summary = report(
      reportNpmNone,
      config({
        directory: testDirectory("npm-none"),
        levels: { low: true },
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("fails with error code ENOTFOUND on a non-existent site", async () => {
    try {
      await auditWithFullConfig(
        config({
          directory: testDirectory("npm-low"),
          levels: { low: true },
          registry: "https://registry.nonexistentdomain0000000000.com",
        }),
      );
    } catch (error) {
      expect((error as Error).message).to.include("ENOTFOUND");
      return;
    }
    throw new Error("Expected an error to be thrown");
  });
  it("reports summary with no vulnerabilities when critical devDependency and skip-dev is true", () => {
    const summary = report(
      reportNpmSkipDevelopment,
      config({
        directory: testDirectory("npm-skip-dev"),
        "skip-dev": true,
        "report-type": "important",
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  // it("fails errors with code ENOAUDIT on a valid site with no audit", (done) => {
  //   audit(
  //     config({
  //       directory: testDirectory("npm-low"),
  //       levels: { low: true },
  //       registry: "https://example.com",
  //     })
  //   ).catch((err) => {
  //     expect(err.message).to.include("code ENOAUDIT");
  //     done();
  //   });
  // });
  // it("passes using --pass-enoaudit", () => {
  //   const directory = testDirectory("npm-500");
  //   return audit(
  //     config({
  //       directory,
  //       "pass-enoaudit": true,
  //       _npm: path.join(directory, "npm"),
  //     })
  //   );
  // });
});
