const SUPPORTED_SEVERITY_LEVELS = new Set()
  .add('critical')
  .add('high')
  .add('moderate')
  .add('low');

class Model {
  constructor(config) {
    this.whitelistedModuleNames = config.whitelist;
    this.whitelistedAdvisotryIds = config.advisories;
    this.whitelistedModulesFound = [];
    this.whitelistedAdvisoriesFound = [];
    this.advisoriesFound = [];

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
    this.foundSeverities = new Set();
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

    this.advisoriesFound.push(advisory.id);
    this.foundSeverities.add(advisory.severity);
  }

  compute(parsedOutput) {
    Object.keys(parsedOutput.advisories)
      // Get the advisories values (Object.values not supported in Node 6)
      .map(k => parsedOutput.advisories[k])
      .forEach(a => this.process(a));

    this.failedLevelsFound = [...this.foundSeverities.values()];
    this.failedLevelsFound.sort();
    return this.getSummary();
  }

  getSummary() {
    return {
      advisoriesFound: this.advisoriesFound,
      failedLevelsFound: this.failedLevelsFound,
      whitelistedAdvisoriesFound: this.whitelistedAdvisoriesFound,
      whitelistedModulesFound: this.whitelistedModulesFound,
    };
  }
}

module.exports = Model;
