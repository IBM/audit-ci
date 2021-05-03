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

describe("npm7-auditer", function testNpm7Auditer() {
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
        advisoriesFound: [663],
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
        advisoriesFound: [690],
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
        advisoriesFound: [658],
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
  it("[DEPRECATED - advisories] ignores an advisory if it is whitelisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        allowlist: Allowlist.mapConfigToAllowlist({ advisories: [658] }),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: [658],
      })
    );
  });
  it("ignores an advisory if it is allowlisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([658]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: [658],
      })
    );
  });
  it("[DEPRECATED - advisories] does not ignore an advisory that is not whitelisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        allowlist: Allowlist.mapConfigToAllowlist({ advisories: [659] }),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: [659],
        failedLevelsFound: ["moderate"],
        advisoriesFound: [658],
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
        advisoriesFound: [658],
      })
    );
  });
  it("[DEPRECATED - path-whitelist] reports only vulnerabilities with a not whitelisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: Allowlist.mapConfigToAllowlist({
          "path-whitelist": ["880|github-build>axios"],
        }),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: ["880|github-build>axios"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: [880],
      })
    );
  });
  it("reports only vulnerabilities with a not allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["880|github-build>axios"]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: ["880|github-build>axios"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: [880],
      })
    );
  });
  it("[DEPRECATED - path-whitelist] whitelist all vulnerabilities with a whitelisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: Allowlist.mapConfigToAllowlist({
          "path-whitelist": ["880|axios", "880|github-build>axios"],
        }),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: ["880|axios", "880|github-build>axios"],
      })
    );
  });
  it("allowlist all vulnerabilities with a allowlisted path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["880|axios", "880|github-build>axios"]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: ["880|axios", "880|github-build>axios"],
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
        advisoriesFound: [786],
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
});
