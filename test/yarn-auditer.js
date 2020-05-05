/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { expect } = require("chai");
const path = require("path");
const audit = require("../lib/audit").bind(null, "yarn");

function config(additions) {
  const defaultConfig = {
    levels: {
      low: false,
      moderate: false,
      high: false,
      critical: false,
    },
    "report-type": "important",
    advisories: [],
    whitelist: [],
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
describe("yarn-auditer", function testYarnAuditer() {
  this.slow(3000);
  it("prints full report with critical severity", () => {
    return audit(
      config({
        directory: testDir("yarn-critical"),
        levels: { critical: true },
        "report-type": "full",
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: ["critical"],
        advisoriesFound: [663],
      });
    });
  });
  it("does not report critical severity if it set to false", () => {
    return audit(
      config({
        directory: testDir("yarn-critical"),
        levels: { critical: false },
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it("reports summary with high severity", () => {
    return audit(
      config({
        directory: testDir("yarn-high"),
        levels: { high: true },
        "report-type": "summary",
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: ["high"],
        advisoriesFound: [690],
      });
    });
  });
  it("reports important info with moderate severity", () => {
    return audit(
      config({
        directory: testDir("yarn-moderate"),
        levels: { moderate: true },
        "report-type": "important",
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: ["moderate"],
        advisoriesFound: [658],
      });
    });
  });
  it("does not report moderate severity if it set to false", () => {
    return audit(
      config({
        directory: testDir("yarn-moderate"),
        levels: { moderate: false },
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it("ignores an advisory if it is whitelisted", () => {
    return audit(
      config({
        directory: testDir("yarn-moderate"),
        levels: { moderate: true },
        advisories: [658],
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [658],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it("does not ignore an advisory that is not whitelisted", () => {
    return audit(
      config({
        directory: testDir("yarn-moderate"),
        levels: { moderate: true },
        advisories: [659],
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedPathsFound: [],
        whitelistedAdvisoriesNotFound: [659],
        failedLevelsFound: ["moderate"],
        advisoriesFound: [658],
      });
    });
  });
  it("reports low severity", () => {
    return audit(
      config({
        directory: testDir("yarn-low"),
        levels: { low: true },
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: ["low"],
        advisoriesFound: [722],
      });
    });
  });
  it("passes with no vulnerabilities", () => {
    return audit(
      config({
        directory: testDir("yarn-none"),
        levels: { low: true },
      }),
      (summary) => summary
    ).then((summary) => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it("doesn't use the registry flag since it's not supported in Yarn yet", () => {
    return audit(
      config({
        directory: testDir("yarn-low"),
        levels: { low: true },
        registry: "https://example.com",
      }),
      (summary) => summary
    );
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
  // it('passes using --pass-enoaudit', () => {
  //   const directory = testDir('yarn-503');
  //   return audit(
  //     config({
  //       directory,
  //       'pass-enoaudit': true,
  //       _yarn: path.join(directory, 'yarn'),
  //     })
  //   );
  // });
});
