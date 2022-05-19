// @ts-check
const path = require("path");
const { default: Allowlist } = require("../dist/allowlist");
const { mapVulnerabilityLevelInput } = require("../dist/map-vulnerability");

function summaryWithDefault(additions = {}) {
  const summary = {
    allowlistedModulesFound: [],
    allowlistedAdvisoriesFound: [],
    allowlistedAdvisoriesNotFound: [],
    allowlistedPathsFound: [],
    allowlistedModulesNotFound: [],
    allowlistedPathsNotFound: [],
    failedLevelsFound: [],
    advisoriesFound: [],
    advisoryPathsFound: [],
  };
  return { ...summary, ...additions };
}

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
  const levels = mapVulnerabilityLevelInput(additions.levels || {});
  return {
    ...defaultConfig,
    ...additions,
    levels: { ...defaultConfig.levels, ...levels },
  };
}

function testDirectory(s) {
  return path.resolve(__dirname, s);
}

module.exports = {
  summaryWithDefault,
  config,
  testDirectory,
};
