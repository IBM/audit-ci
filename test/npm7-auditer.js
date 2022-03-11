const { expect } = require("chai");
const { audit, report } = require("../lib/npm-auditer");
const Allowlist = require("../lib/allowlist");
const { summaryWithDefault, config, testDir } = require("./common");

const reportNpmCritical = require("./npm-critical/npm7-output.json");
const reportNpmHighSeverity = require("./npm-high/npm7-output.json");
const reportNpmModerateSeverity = require("./npm-moderate/npm7-output.json");
const reportNpmAllowlistedPath = require("./npm-allowlisted-path/npm7-output.json");
const reportNpmLow = require("./npm-low/npm7-output.json");
const reportNpmNone = require("./npm-none/npm7-output.json");
const reportNpmSkipDev = require("./npm-skip-dev/npm-output.json");

describe("npm7-auditer", () => {
  it("prints full report with critical severity", () => {
    const summary = report(
      reportNpmCritical,
      config({
        directory: testDir("npm-critical"),
        levels: { critical: true },
        "report-type": "full",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical"],
        advisoriesFound: [1040620],
      })
    );
  });
  it("does not report critical severity if it set to false", () => {
    const summary = report(
      reportNpmCritical,
      config({
        directory: testDir("npm-critical"),
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
        directory: testDir("npm-high"),
        levels: { high: true },
        "report-type": "summary",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["high"],
        advisoriesFound: [1039985],
      })
    );
  });
  it("reports important info with moderate severity", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: [1040003],
      })
    );
  });
  it("does not report moderate severity if it set to false", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
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
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([1040003]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: [1040003],
      })
    );
  });
  it("does not ignore an advisory that is not allowlisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([659]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: [659],
        failedLevelsFound: ["moderate"],
        advisoriesFound: [1040003],
      })
    );
  });
  it("reports only vulnerabilities with a not allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "1040655|axios",
          "1040655|github-build>*",
          "1038442|axios>follow-redirects",
          "1038442|github-build>axios>follow-redirects",
          "*|github-build>axios",
        ]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        advisoriesFound: [1038749, 1039327, 1038495],
        failedLevelsFound: ["high"],
        allowlistedPathsFound: [
          "1038749|github-build>axios",
          "1039327|github-build>axios",
          "1040655|axios",
          "1040655|github-build>axios",
          "1038442|github-build>axios>follow-redirects",
          "1038442|axios>follow-redirects",
        ],
      })
    );
  });
  it("allowlist all vulnerabilities with an allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "1038749|axios",
          "1039327|axios",
          "1040655|axios",
          "1038442|axios>follow-redirects",
          "1038442|github-build>axios>follow-redirects",
          "1038495|axios>follow-redirects",
          "1038495|github-build>axios>follow-redirects",
          "1038749|github-build>axios",
          "1039327|github-build>axios",
          "1040655|github-build>axios",
        ]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "1038749|axios",
          "1038749|github-build>axios",
          "1039327|axios",
          "1039327|github-build>axios",
          "1040655|axios",
          "1040655|github-build>axios",
          "1038442|github-build>axios>follow-redirects",
          "1038442|axios>follow-redirects",
          "1038495|github-build>axios>follow-redirects",
          "1038495|axios>follow-redirects",
        ],
      })
    );
  });
  it("allowlist all vulnerabilities matching a wildcard allowlist path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["*|axios", "*|github-build>*", "*|axios>*"]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: [
          "1038749|axios",
          "1038749|github-build>axios",
          "1039327|axios",
          "1039327|github-build>axios",
          "1040655|axios",
          "1040655|github-build>axios",
          "1038442|github-build>axios>follow-redirects",
          "1038442|axios>follow-redirects",
          "1038495|github-build>axios>follow-redirects",
          "1038495|axios>follow-redirects",
        ],
      })
    );
  });
  it("reports low severity", () => {
    const summary = report(
      reportNpmLow,
      config({
        directory: testDir("npm-low"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["low"],
        advisoriesFound: [1038984],
      })
    );
  });
  it("passes with no vulnerabilities", () => {
    const summary = report(
      reportNpmNone,
      config({
        directory: testDir("npm-none"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("fails with error code ENOTFOUND on a non-existent site", (done) => {
    audit(
      config({
        directory: testDir("npm-low"),
        levels: { low: true },
        registry: "https://registry.nonexistentdomain0000000000.com",
      })
    ).catch((err) => {
      expect(err.message).to.include("ENOTFOUND");
      done();
    });
  });
  it("reports summary with no vulnerabilities when critical devDependency and skip-dev is true", () => {
    const summary = report(
      reportNpmSkipDev,
      config({
        directory: testDir("npm-skip-dev"),
        "skip-dev": true,
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
});
