import { ok } from "assert";
import { expect } from "chai";
import childProcess from "child_process";
import semver from "semver";
import Allowlist from "../lib/allowlist";
import audit from "../lib/audit";
import {
  config as baseConfig,
  summaryWithDefault,
  testDirectory,
} from "./common";

function config(
  additions: Omit<Parameters<typeof baseConfig>[0], "package-manager">
) {
  return baseConfig({ ...additions, "package-manager": "yarn" });
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
        directory: testDirectory("yarn-critical"),
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
  it("does not report critical severity if it set to false", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-critical"),
        levels: { critical: false },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with high severity", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-high"),
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
  it("reports important info with moderate severity", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
        allowlist: new Allowlist(["GHSA-hm7f-rq7q-j9xp"]),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        allowlistedAdvisoriesFound: ["GHSA-hm7f-rq7q-j9xp"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: ["GHSA-rvg8-pwq2-xj7q|base64url"],
      })
    );
  });
  it("does not report moderate severity if it set to false", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
        levels: { moderate: false },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("ignores an advisory if it is allowlisted", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          "GHSA-rvg8-pwq2-xj7q",
          "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
        ]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        allowlistedPathsFound: ["GHSA-hm7f-rq7q-j9xp|@builder.io/qwik"],
      })
    );
  });
  it("ignores an advisory if it is allowlisted using a NSPRecord", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist([
          {
            "GHSA-rvg8-pwq2-xj7q": {
              active: true,
            },
          },
          {
            "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik": {
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
        allowlistedPathsFound: ["GHSA-hm7f-rq7q-j9xp|@builder.io/qwik"],
      })
    );
  });
  it("does not ignore an advisory that is not allowlisted", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
        levels: { moderate: true },
        allowlist: new Allowlist(["GHSA-cff4-rrq6-h78w"]),
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q", "GHSA-hm7f-rq7q-j9xp"],
        advisoryPathsFound: [
          "GHSA-rvg8-pwq2-xj7q|base64url",
          "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
        ],
      })
    );
  });
  it("does not ignore an advisory that is not allowlisted using a NSPRecord", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
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
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q", "GHSA-hm7f-rq7q-j9xp"],
        advisoryPathsFound: [
          "GHSA-rvg8-pwq2-xj7q|base64url",
          "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
        ],
      })
    );
  });
  it("ignores an advisory that has not expired", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-rvg8-pwq2-xj7q"],
        allowlistedPathsFound: ["GHSA-hm7f-rq7q-j9xp|@builder.io/qwik"],
      })
    );
  });
  it("does not ignore an advisory that has expired", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-moderate"),
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
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesNotFound: ["GHSA-cff4-rrq6-h78w"],
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-rvg8-pwq2-xj7q", "GHSA-hm7f-rq7q-j9xp"],
        advisoryPathsFound: [
          "GHSA-rvg8-pwq2-xj7q|base64url",
          "GHSA-hm7f-rq7q-j9xp|@builder.io/qwik",
        ],
      })
    );
  });
  it("reports low severity", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-low"),
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
  it("passes with no vulnerabilities", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-none"),
        levels: { low: true },
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("doesn't use the registry flag since it's not supported in Yarn yet", () =>
    audit(
      config({
        directory: testDirectory("yarn-low"),
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
          directory: testDirectory("yarn-berry-moderate"),
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
    }
  );
  (canRunYarnBerry ? it : it.skip)(
    "[Yarn Berry] does not report moderate severity if it set to false",
    async () => {
      const summary = await audit(
        config({
          directory: testDirectory("yarn-berry-moderate"),
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
          directory: testDirectory("yarn-berry-moderate"),
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
  (canRunYarnBerry ? it : it.skip)(
    "[Yarn Berry] ignores an advisory if it is allowlisted using a NSPRecord",
    async () => {
      const summary = await audit(
        config({
          directory: testDirectory("yarn-berry-moderate"),
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
    }
  );
  it("reports summary with no vulnerabilities when critical devDependency and skip-dev is true", async () => {
    const summary = await audit(
      config({
        directory: testDirectory(
          canRunYarnBerry ? "yarn-berry-skip-dev" : "yarn-skip-dev"
        ),
        "skip-dev": true,
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with no vulnerabilities in yarn v1 workspace", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-workspace-empty"),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(summaryWithDefault());
  });
  it("reports summary with vulnerabilities in yarn v1 workspaces", async () => {
    // TODO: There's a bug with yarn classic workspaces and failing to audit
    // devDependencies:
    // https://github.com/yarnpkg/yarn/issues/7047
    // It doesn't report any vulnerabilities at all. The following directory should
    // contain a critical vulnerability in devDependencies.
    const summary = await audit(
      config({
        directory: testDirectory("yarn-workspace"),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (_summary) => _summary
    );
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["high", "moderate"],
        advisoriesFound: ["GHSA-38f5-ghc2-fcmv", "GHSA-rvg8-pwq2-xj7q"],
        advisoryPathsFound: [
          "GHSA-38f5-ghc2-fcmv|audit-ci-yarn-workspace-high-vulnerability>cryo",
          "GHSA-rvg8-pwq2-xj7q|audit-ci-yarn-workspace-moderate-vulnerability>base64url",
        ],
      })
    );
  });
  (canRunYarnBerry ? it : it.skip)(
    "reports summary with no vulnerabilities in yarn berry workspace",
    async () => {
      const summary = await audit(
        config({
          directory: testDirectory("yarn-berry-workspace-empty"),
          levels: { moderate: true },
          "report-type": "important",
        }),
        (_summary) => _summary
      );
      expect(summary).to.eql(summaryWithDefault());
    }
  );
  (canRunYarnBerry ? it : it.skip)(
    "reports summary with vulnerabilities in yarn berry workspaces",
    async () => {
      const summary = await audit(
        config({
          directory: testDirectory("yarn-berry-workspace"),
          levels: { moderate: true },
          "report-type": "important",
        }),
        (_summary) => _summary
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["critical", "high", "moderate"],
          advisoriesFound: [
            "GHSA-28xh-wpgr-7fm8",
            "GHSA-38f5-ghc2-fcmv",
            "GHSA-rvg8-pwq2-xj7q",
          ],
          advisoryPathsFound: [
            "GHSA-28xh-wpgr-7fm8|open",
            "GHSA-38f5-ghc2-fcmv|cryo",
            "GHSA-rvg8-pwq2-xj7q|base64url",
          ],
        })
      );
    }
  );
  (canRunYarnBerry ? it : it.skip)(
    "reports summary with vulnerabilities in yarn berry workspaces with skip-dev=true",
    async () => {
      const summary = await audit(
        config({
          directory: testDirectory("yarn-berry-workspace"),
          levels: { moderate: true },
          "skip-dev": true,
          "report-type": "important",
        }),
        (_summary) => _summary
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["high", "moderate"],
          advisoriesFound: ["GHSA-38f5-ghc2-fcmv", "GHSA-rvg8-pwq2-xj7q"],
          advisoryPathsFound: [
            "GHSA-38f5-ghc2-fcmv|cryo",
            "GHSA-rvg8-pwq2-xj7q|base64url",
          ],
        })
      );
    }
  );
  (canRunYarnBerry ? it : it.skip)(
    "reports summary with vulnerabilities in yarn berry workspaces with extra-args: --environment production",
    async () => {
      const summary = await audit(
        config({
          directory: testDirectory("yarn-berry-workspace"),
          levels: { moderate: true },
          "extra-args": ["--environment", "production"],
          "report-type": "important",
        }),
        (_summary) => _summary
      );
      expect(summary).to.eql(
        summaryWithDefault({
          failedLevelsFound: ["high", "moderate"],
          advisoriesFound: ["GHSA-38f5-ghc2-fcmv", "GHSA-rvg8-pwq2-xj7q"],
          advisoryPathsFound: [
            "GHSA-38f5-ghc2-fcmv|cryo",
            "GHSA-rvg8-pwq2-xj7q|base64url",
          ],
        })
      );
    }
  );
  it("does not report duplicate paths", async () => {
    const summary = await audit(
      config({
        directory: testDirectory("yarn-duplicate-paths"),
        levels: { high: true },
        "report-type": "summary",
      }),
      (_summary) => _summary
    );
    ok(summary);
    expect(summary.advisoryPathsFound).to.eql([
      ...new Set(summary.advisoryPathsFound),
    ]);
  });
  // it('prints unexpected https://registry.yarnpkg.com 503 error message', () => {
  //   const directory = testDirectory('yarn-503');
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
  //   const directory = testDirectory("yarn-503");
  //   return audit(
  //     config({
  //       directory,
  //       "pass-enoaudit": true,
  //       _yarn: path.join(directory, "yarn"),
  //     })
  //   );
  // });
});
