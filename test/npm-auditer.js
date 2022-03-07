const { expect } = require("chai");
const { audit, report } = require("../lib/npm-auditer");
const Allowlist = require("../lib/allowlist");
const { summaryWithDefault, config, testDir } = require("./common");

const reportNpmCritical = require("./npm-critical/npm-output.json");
const reportNpmHighSeverity = require("./npm-high/npm-output.json");
const reportNpmModerateSeverity = require("./npm-moderate/npm-output.json");
const reportNpmAllowlistedPath = require("./npm-allowlisted-path/npm-output.json");
const reportNpmLow = require("./npm-low/npm-output.json");
const reportNpmNone = require("./npm-none/npm-output.json");
const reportNpmSkipDev = require("./npm-skip-dev/npm-output.json");

// To modify what slow times are, need to use
// function() {} instead of () => {}
describe("npm-auditer", () => {
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
        advisoriesFound: [1004291],
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
        advisoriesFound: [1003653],
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
        advisoriesFound: [1003671],
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
        allowlist: Allowlist.mapConfigToAllowlist({ advisories: [1003671] }),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: [1003671],
      })
    );
  });
  it("ignores an advisory if it is allowlisted", () => {
    const summary = report(
      reportNpmModerateSeverity,
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([1003671]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: [1003671],
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
        advisoriesFound: [1003671],
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
        advisoriesFound: [1003671],
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
  it("allowlist all vulnerabilities matching a wildcard allowlist path", () => {
    const summary = report(
      reportNpmAllowlistedPath,
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: new Allowlist(["*|axios", "*|github-build>*"]),
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
        advisoriesFound: [1004319],
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
  // it("fails errors with code ENOAUDIT on a valid site with no audit", (done) => {
  //   audit(
  //     config({
  //       directory: testDir("npm-low"),
  //       levels: { low: true },
  //       registry: "https://example.com",
  //     })
  //   ).catch((err) => {
  //     expect(err.message).to.include("code ENOAUDIT");
  //     done();
  //   });
  // });
  // it("passes using --pass-enoaudit", () => {
  //   const directory = testDir("npm-500");
  //   return audit(
  //     config({
  //       directory,
  //       "pass-enoaudit": true,
  //       _npm: path.join(directory, "npm"),
  //     })
  //   );
  // });
});
