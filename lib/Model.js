const SUPPORTED_SEVERITY_LEVELS = new Set()
  .add('critical')
  .add('high')
  .add('moderate')
  .add('low');

class Model {
  constructor(config) {
    this.whitelistedModuleNames = config.whitelist;
    this.whitelistedAdvisotryIds = config.advisories;

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
  }

  compute(parsedOutput) {
    const ret = {
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      advisoriesFound: [],
    };

    const foundSeverities = new Set();

    Object.keys(parsedOutput.advisories)
      // Get the advisories values (Object.values not supported in Node 6)
      .map(k => parsedOutput.advisories[k])
      // Remove advisories that have a level that doesn't fail the build
      .filter(curr => this.failingSverities[curr.severity])
      .forEach(curr => {
        if (this.whitelistedModuleNames.some(m => m === curr.module_name)) {
          ret.whitelistedModulesFound.push(curr.module_name);
          return;
        }

        if (this.whitelistedAdvisotryIds.some(a => Number(a) === curr.id)) {
          ret.whitelistedAdvisoriesFound.push(curr.id);
          return;
        }

        ret.advisoriesFound.push(curr.id);
        foundSeverities.add(curr.severity);
      });

    ret.failedLevelsFound = [...foundSeverities.values()];
    return ret;
  }
}

module.exports = Model;
