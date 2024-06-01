import { describe, expect, it } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { report } from "../lib/pnpm-auditor.js";
import {
  config as baseConfig,
  summaryWithDefault,
  testDirectory,
} from "./common.js";

import reportPnpmAllowlistedPath from "./pnpm-allowlisted-path/pnpm-output.json";
import reportPnpmCritical from "./pnpm-critical/pnpm-output.json";
import reportPnpmHighSeverity from "./pnpm-high/pnpm-output.json";
import reportPnpmLow from "./pnpm-low/pnpm-output.json";
import reportPnpmModerateSeverity from "./pnpm-moderate/pnpm-output.json";
import reportPnpmNone from "./pnpm-none/pnpm-output.json";
import reportPnpmSkipDevelopment from "./pnpm-skip-dev/pnpm-output.json";

function config(
  additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">,
) {
  return baseConfig({ ...additions, "package-manager": "pnpm" });
}

// To modify what slow times are, need to use
// function() {} instead of () => {}
describe("pnpm-auditor", () => {
  it("prints full report with critical severity", () => {
    const summary = report(
      reportPnpmCritical,
      config({
        directory: testDirectory("pnpm-critical"),
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
      reportPnpmCritical,
      config({
        directory: testDirectory("pnpm-critical"),
        levels: { critical: false },
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with high severity", () => {
    const summary = report(
      reportPnpmHighSeverity,
      config({
        directory: testDirectory("pnpm-high"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
        levels: { moderate: false },
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("ignores an advisory if it is allowlisted", () => {
    const summary = report(
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmModerateSeverity,
      config({
        directory: testDirectory("pnpm-moderate"),
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
      reportPnpmAllowlistedPath,
      config({
        directory: testDirectory("pnpm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
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
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
        ],
        advisoryPathsFound: [
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
        ],
      }),
    );
  });
  it("allowlist all vulnerabilities with an allowlisted path", () => {
    const summary = report(
      reportPnpmAllowlistedPath,
      config({
        directory: testDirectory("pnpm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
        ]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
        ],
      }),
    );
  });
  it("allowlist all vulnerabilities matching a wildcard allowlist path", () => {
    const summary = report(
      reportPnpmAllowlistedPath,
      config({
        directory: testDirectory("pnpm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["*|axios", "*|axios>*"]),
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
        ],
      }),
    );
  });
  it("reports low severity", () => {
    const summary = report(
      reportPnpmLow,
      config({
        directory: testDirectory("pnpm-low"),
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
      reportPnpmNone,
      config({
        directory: testDirectory("pnpm-none"),
        levels: { low: true },
      }),
      (_summary) => _summary,
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with no vulnerabilities when critical devDependency and skip-dev is true", () => {
    const summary = report(
      reportPnpmSkipDevelopment,
      config({
        directory: testDirectory("pnpm-skip-dev"),
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
  //       directory: testDirectory("pnpm-low"),
  //       levels: { low: true },
  //       registry: "https://example.com",
  //     })
  //   ).catch((err) => {
  //     expect(err.message).to.include("code ENOAUDIT");
  //     done();
  //   });
  // });
  // it("passes using --pass-enoaudit", () => {
  //   const directory = testDirectory("pnpm-500");
  //   return audit(
  //     config({
  //       directory,
  //       "pass-enoaudit": true,
  //       _pnpm: path.join(directory, "pnpm"),
  //     })
  //   );
  // });
});
