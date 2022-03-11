const path = require("path");
const Allowlist = require("../lib/allowlist");
const { mapVulnerabilityLevelInput } = require("../lib/map-vulnerability");

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
  const { levels: _unusedLevels, ...rest } = additions;
  return {
    ...defaultConfig,
    ...rest,
    levels: { ...defaultConfig.levels, ...levels },
  };
}

function testDir(s) {
  return path.resolve(__dirname, s);
}

module.exports = {
  summaryWithDefault,
  config,
  testDir,
};
