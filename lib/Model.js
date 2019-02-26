/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
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
        `Unsupported severity levels found: ${unsupported.join(', ')}`
      );
    }
    this.failingSeverities = config.levels;

    this.whitelistedModuleNames = config.whitelist;
    this.whitelistedAdvisoryIds = config.advisories;

    this.whitelistedModulesFound = [];
    this.whitelistedAdvisoriesFound = [];
    this.advisoriesFound = [];
  }

  process(advisory) {
    if (!this.failingSeverities[advisory.severity]) {
      return;
    }

    if (this.whitelistedModuleNames.some(m => m === advisory.module_name)) {
      if (this.whitelistedModulesFound.indexOf(advisory.module_name) === -1) {
        this.whitelistedModulesFound.push(advisory.module_name);
      }
      return;
    }

    if (this.whitelistedAdvisoryIds.some(a => Number(a) === advisory.id)) {
      this.whitelistedAdvisoriesFound.push(advisory.id);
      return;
    }

    this.advisoriesFound.push(advisory);
  }

  load(parsedOutput) {
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

    const advisoriesFound = this.advisoriesFound.map(advisoryMapper);

    return {
      advisoriesFound,
      failedLevelsFound,
      whitelistedAdvisoriesFound: this.whitelistedAdvisoriesFound,
      whitelistedModulesFound: this.whitelistedModulesFound,
    };
  }
}

module.exports = Model;
