const { expect } = require("chai");
const childProcess = require("child_process");
const path = require("path");
const semver = require("semver");
const audit = require("../lib/audit").bind(null, "yarn");
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
    "skip-dev": false,
  };
  return { ...defaultConfig, ...additions };
}

function testDir(s) {
  return path.resolve(__dirname, s);
}

const canRunYarnBerry = semver.gte(
  childProcess.execSync("node -v").toString().replace("\n", ""),
  "12.13.0"
);

// To modify what slow times are, need to use
// function() {} instead of () => {}
describe("yarn-auditer", function testYarnAuditer() {
  this.slow(3000);
  it("prints full report with critical severity", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-critical"),
        levels: { critical: true },
        "report-type": "full",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical"],
        advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
      })
    );
  });
  it("does not report critical severity if it set to false", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-critical"),
        levels: { critical: false },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with high severity", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-high"),
        levels: { high: true },
        "report-type": "summary",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["high"],
        advisoriesFound: ["GHSA-38f5-ghc2-fcmv"],
      })
    );
  });
  it("reports important info with moderate severity", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-moderate"),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
      })
    );
  });
  it("does not report moderate severity if it set to false", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-moderate"),
        levels: { moderate: false },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("ignores an advisory if it is allowlisted", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-moderate"),
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
  it("does not ignore an advisory that is not allowlisted", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-moderate"),
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
      })
    );
  });
  it("reports low severity", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-low"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["low"],
        advisoriesFound: ["GHSA-c6rq-rjc2-86v2"],
      })
    );
  });
  it("passes with no vulnerabilities", async () => {
    const summary = await audit(
      config({
        directory: testDir("yarn-none"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("doesn't use the registry flag since it's not supported in Yarn yet", () =>
    audit(
      config({
        directory: testDir("yarn-low"),
        levels: { low: true },
        registry: "https://example.com",
      }),
      (_summary) => _summary
    ));
  (canRunYarnBerry ? it : it.skip)(
    "[Yarn Berry] reports important info with moderate severity",
    async () => {
      const summary = await audit(
        config({
          directory: testDir("yarn-berry-moderate"),
          levels: { moderate: true },
          "report-type": "important",
        }),
        (_summary) => _summary
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["moderate"],
          advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        })
      );
    }
  );
  (canRunYarnBerry ? it : it.skip)(
    "[Yarn Berry] does not report moderate severity if it set to false",
    async () => {
      const summary = await audit(
        config({
          directory: testDir("yarn-berry-moderate"),
          levels: { moderate: false },
        }),
        (_summary) => _summary
      );
      expect(summary).to.eql(summaryWithDefault());
    }
  );
  (canRunYarnBerry ? it : it.skip)(
    "[Yarn Berry] ignores an advisory if it is allowlisted",
    async () => {
      const summary = await audit(
        config({
          directory: testDir("yarn-berry-moderate"),
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
    }
  );
  it("reports summary with no vulnerabilities when critical devDependency and skip-dev is true", async () => {
    const summary = await audit(
      config({
        directory: testDir(
          canRunYarnBerry ? "yarn-berry-skip-dev" : "yarn-skip-dev"
        ),
        "skip-dev": true,
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  // it('prints unexpected https://registry.yarnpkg.com 503 error message', () => {
  //   const directory = testDir('yarn-503');
  //   const errorMessagePath = path.resolve(directory, 'error-message');
  //   const errorMessage = require(errorMessagePath); // eslint-disable-line

  //   return audit(
  //     config({
  //       directory,
  //       _yarn: path.join(directory, 'yarn'),
  //     })
  //   )
  //     .then(() => {
  //       // Since we expect an error the promise should never resolve
  //       throw new Error();
  //     })
  //     .catch(err => {
  //       expect(err.toString()).to.contain(errorMessage);
  //     });
  // });
  // it("passes using --pass-enoaudit", () => {
  //   const directory = testDir("yarn-503");
  //   return audit(
  //     config({
  //       directory,
  //       "pass-enoaudit": true,
  //       _yarn: path.join(directory, "yarn"),
  //     })
  //   );
  // });
});
