const { expect } = require("chai");
const path = require("path");
const audit = require("../lib/audit").bind(null, "npm");
const Allowlist = require("../lib/allowlist");
const { summaryWithDefault } = require("./common");

function config(additions) {
  const defaultConfig = {
    levels: {
      low: false,
      moderate: false,
      high: false,
      critical: false,
    },
    "report-type": "important",
    allowlist: new Allowlist(),
    "show-not-found": false,
    "retry-count": 5,
    directory: "./",
    registry: undefined,
    "pass-enoaudit": false,
  };
  return { ...defaultConfig, ...additions };
}

function testDir(s) {
  return path.resolve(__dirname, s);
}

// To modify what slow times are, need to use
// function() {} instead of () => {}
describe("npm-auditer", function testNpmAuditer() {
  this.slow(6000);
  it("prints full report with critical severity", async () => {
    const summary = await audit(
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
  it("does not report critical severity if it set to false", async () => {
    const summary = await audit(
      config({
        directory: testDir("npm-critical"),
        levels: { critical: false },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with high severity", async () => {
    const summary = await audit(
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
  it("reports important info with moderate severity", async () => {
    const summary = await audit(
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
  it("does not report moderate severity if it set to false", async () => {
    const summary = await audit(
      config({
        directory: testDir("npm-moderate"),
        levels: { moderate: false },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("[DEPRECATED - advisories] ignores an advisory if it is whitelisted", async () => {
    const summary = await audit(
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
  it("ignores an advisory if it is allowlisted", async () => {
    const summary = await audit(
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
  it("[DEPRECATED - advisories] does not ignore an advisory that is not whitelisted", async () => {
    const summary = await audit(
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
  it("does not ignore an advisory that is not allowlisted", async () => {
    const summary = await audit(
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
  it("[DEPRECATED - path-whitelist] reports only vulnerabilities with a not whitelisted path", async () => {
    const summary = await audit(
      config({
        directory: testDir("npm-allowlisted-path"),
        levels: { moderate: true },
        allowlist: Allowlist.mapConfigToAllowlist({
          "path-whitelist": ["axios|github-build"],
        }),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedPathsFound: ["axios|github-build"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["axios"],
      })
    );
  });
  it("reports only vulnerabilities with a not allowlisted path", async () => {
    const summary = await audit(
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
  it("[DEPRECATED - path-whitelist] whitelist all vulnerabilities with a whitelisted path", async () => {
    const summary = await audit(
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
  it("allowlist all vulnerabilities with a allowlisted path", async () => {
    const summary = await audit(
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
  it("reports low severity", async () => {
    const summary = await audit(
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
  it("passes with no vulnerabilities", async () => {
    const summary = await audit(
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
  // available in npm 6 only
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
