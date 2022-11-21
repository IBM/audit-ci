// @ts-check
const { expect } = require("chai");
const { audit, report } = require("../dist/npm-auditer");
const { default: Allowlist } = require("../dist/allowlist");
const {
  summaryWithDefault,
  config: baseConfig,
  testDirectory,
} = require("./common");

const reportNpmCritical = require("./npm-critical/npm7-output.json");
const reportNpmHighSeverity = require("./npm-high/npm7-output.json");
const reportNpmModerateSeverity = require("./npm-moderate/npm7-output.json");
const reportNpmAllowlistedPath = require("./npm-allowlisted-path/npm7-output.json");
const reportNpmLow = require("./npm-low/npm7-output.json");
const reportNpmNone = require("./npm-none/npm7-output.json");
const reportNpmSkipDevelopment = require("./npm-skip-dev/npm-output.json");

function config(additions) {
  return baseConfig({ ...additions, "package-manager": "npm" });
}

describe("npm7-auditer", () => {
  it("prints full report with critical severity", () => {
    const summary = report(
      reportNpmCritical,
      config({
        directory: testDirectory("npm-critical"),
        levels: { critical: true },
        "report-type": "full",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical"],
        advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
        advisoryPathsFound: ["GHSA-28xh-wpgr-7fm8|open"],
      })
    );
  });
  it("does not report critical severity if it set to false", () => {
    const summary = report(
      reportNpmCritical,
      config({
        directory: testDirectory("npm-critical"),
        levels: { critical: false },
      }),
      (_summary) => _summary
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["high"],
        advisoriesFound: ["GHSA-38f5-ghc2-fcmv"],
        advisoryPathsFound: ["GHSA-38f5-ghc2-fcmv|cryo"],
      })
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      })
    );
  });
  it("does not report moderate severity if it set to false", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDirectory("npm-moderate"),
        levels: { moderate: false },
      }),
      (_summary) => _summary
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
      })
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
      })
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      })
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      })
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
      })
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      })
    );
  });
  it("reports only vulnerabilities with a not allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDirectory("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>*",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
          "*|github-build>axios",
        ]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        advisoriesFound: [
          "GHSA-cph5-m8f7-6c5x",
          "GHSA-4w2v-q235-vp99",
          "GHSA-74fj-2j2h-c42q",
        ],
        failedLevelsFound: ["high"],
        allowlistedPathsFound: [
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
        ],
        advisoryPathsFound: [
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
        ],
      })
    );
  });
  it("allowlist all vulnerabilities with an allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDirectory("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
        ]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
        ],
      })
    );
  });
  it("allowlist all vulnerabilities matching a wildcard allowlist path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDirectory("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["*|axios", "*|github-build>*", "*|axios>*"]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "GHSA-cph5-m8f7-6c5x|axios",
          "GHSA-cph5-m8f7-6c5x|github-build>axios",
          "GHSA-4w2v-q235-vp99|axios",
          "GHSA-4w2v-q235-vp99|github-build>axios",
          "GHSA-42xw-2xvc-qx8m|axios",
          "GHSA-42xw-2xvc-qx8m|github-build>axios",
          "GHSA-pw2r-vq6v-hr8c|github-build>axios>follow-redirects",
          "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|github-build>axios>follow-redirects",
          "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
        ],
      })
    );
  });
  it("reports low severity", () => {
    const summary = report(
      reportNpmLow,
      config({
        directory: testDirectory("npm-low"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["low"],
        advisoriesFound: ["GHSA-c6rq-rjc2-86v2"],
        advisoryPathsFound: ["GHSA-c6rq-rjc2-86v2|chownr"],
      })
    );
  });
  it("passes with no vulnerabilities", () => {
    const summary = report(
      reportNpmNone,
      config({
        directory: testDirectory("npm-none"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("fails with error code ENOTFOUND on a non-existent site", (done) => {
    audit(
      config({
        directory: testDirectory("npm-low"),
        levels: { low: true },
        registry: "https://registry.nonexistentdomain0000000000.com",
      })
    ).catch((error) => {
      expect(error.message).to.include("ENOTFOUND");
      done();
    });
  });
  it("fails with error code ECONNREFUSED on a live site with no registry", (done) => {
    audit(
      config({
        directory: testDirectory("npm-low"),
        levels: { low: true },
        registry: "http://localhost",
      })
    )
      .catch((error) => {
        expect(error.message).to.include("ECONNREFUSED");
        done();
      })
      .catch((error) => done(error));
  });
  it("reports summary with no vulnerabilities when critical devDependency and skip-dev is true", () => {
    const summary = report(
      reportNpmSkipDevelopment,
      config({
        directory: testDirectory("npm-skip-dev"),
        "skip-dev": true,
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
});
