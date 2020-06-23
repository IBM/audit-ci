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

module.exports = { summaryWithDefault };
