const SUPPORTED_SEVERITY_LEVELS = new Set()
  .add('critical')
  .add('high')
  .add('moderate')
  .add('low');

class Model {
  constructor(config) {
    this.whitelistedModuleNames = config.whitelist;
    this.whitelistedAdvisotryIds = config.advisories;
    this.summary = {
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      advisoriesFound: [],
    };

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
      this.summary.whitelistedModulesFound.push(advisory.module_name);
      return;
    }

    if (this.whitelistedAdvisotryIds.some(a => Number(a) === advisory.id)) {
      this.summary.whitelistedAdvisoriesFound.push(advisory.id);
      return;
    }

    this.summary.advisoriesFound.push(advisory.id);
    this.foundSeverities.add(advisory.severity);
  }

  compute(parsedOutput) {
    Object.keys(parsedOutput.advisories)
      // Get the advisories values (Object.values not supported in Node 6)
      .map(k => parsedOutput.advisories[k])
      .forEach(a => this.process(a));

    this.summary.failedLevelsFound = [...this.foundSeverities.values()];
    this.summary.failedLevelsFound.sort();
    return this.summary;
  }
}

module.exports = Model;
