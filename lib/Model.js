const SUPPORTED_SEVERITY_LEVELS = new Set()
  .add('critical')
  .add('high')
  .add('moderate')
  .add('low');

class Model {
  constructor(config) {
    const unsupported = Object.keys(config.levels).filter(
      curr => !SUPPORTED_SEVERITY_LEVELS.has(curr)
    );
    unsupported.sort();
    if (unsupported.length) {
      throw new Error(
        'Unsupported severity levels found: ' + unsupported.join(', ')
      );
    }
    this.failingSverities = config.levels;

    this.whitelistedModuleNames = config.whitelist;
    this.whitelistedAdvisotryIds = config.advisories;

    this.whitelistedModulesFound = [];
    this.whitelistedAdvisoriesFound = [];
    this.advisoriesFound = [];
  }

  process(advisory) {
    if (!this.failingSverities[advisory.severity]) {
      return;
    }

    if (this.whitelistedModuleNames.some(m => m === advisory.module_name)) {
      this.whitelistedModulesFound.push(advisory.module_name);
      return;
    }

    if (this.whitelistedAdvisotryIds.some(a => Number(a) === advisory.id)) {
      this.whitelistedAdvisoriesFound.push(advisory.id);
      return;
    }

    this.advisoriesFound.push(advisory);
  }

  compute(parsedOutput) {
    Object.keys(parsedOutput.advisories)
      // Get the advisories values (Object.values not supported in Node 6)
      .map(k => parsedOutput.advisories[k])
      .forEach(a => this.process(a));

    return this.getSummary();
  }

  getSummary(advisoryMapper = a => a.id) {
    const foundSeverities = new Set();
    this.advisoriesFound.forEach(curr => foundSeverities.add(curr.severity));
    const failedLevelsFound = [...foundSeverities.values()];
    failedLevelsFound.sort();

    return {
      advisoriesFound: this.advisoriesFound.map(advisoryMapper),
      failedLevelsFound: failedLevelsFound,
      whitelistedAdvisoriesFound: this.whitelistedAdvisoriesFound,
      whitelistedModulesFound: this.whitelistedModulesFound,
    };
  }
}

module.exports = Model;
