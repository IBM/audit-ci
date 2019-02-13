/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { runProgram } = require('./common');

class Model {
  constructor(config) {
    this.whitelistedModuleNames = config.whitelist;
    this.whitelistedAdvisotryIds = config.advisories;
    this.failingSverities = config.levels;
  }

  compute(parsedOutput) {
    const ret = {
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: [],
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

        foundSeverities.add(curr.severity);
      });

    ret.failedLevels = [...foundSeverities.values()];
    return ret;
  }
}

function reportAudit(config, parsedOutput, summary) {
  const { whitelist } = config;
  if (whitelist.length) {
    console.log(
      '\x1b[36m%s\x1b[0m',
      'Modules to whitelist: '.concat(whitelist.join(', '), '.')
    );
  }

  if (config.report) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report JSON:');
    console.log(JSON.stringify(parsedOutput, null, 2));
  }

  if (summary.whitelistedModulesFound.length) {
    const found = summary.whitelistedModulesFound.join(', ');
    const msg = `Vulnerable whitelisted modules found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }
  if (summary.whitelistedAdvisoriesFound.length) {
    const found = summary.whitelistedAdvisoriesFound.join(', ');
    const msg = `Vulnerable whitelisted advisories found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }

  if (summary.failedLevelsFound.length) {
    // Get the levels that have failed by filtering the keys with true values
    const err = `Failed security audit due to ${summary.failedLevelsFound.join(
      ', '
    )} vulnerabilities.`;
    throw new Error(err);
  }
  return summary;
}

function runNpmAudit(dir) {
  return Promise.resolve()
    .then(() => runProgram('npm', ['audit', '--json'], dir))
    .then(({ exitCode, stdout, stderr, description }) => {
      if (stderr) {
        throw new Error(
          `Invocation of ${description} failed (exit code: ${exitCode}):\n${stderr}`
        );
      }

      try {
        return JSON.parse(stdout);
      } catch (e) {
        console.log('stdout=\n' + stdout);
        throw e;
      }
    });
}

/**
 * Audit your NPM project!
 *
 * @param {{dir: string, report: boolean, whitelist: string[], advisories: string[], levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `dir`: directory to run npm audit at.
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<any>} Returns the audit report on resolve, `Error` on rejection.
 */
function audit(config) {
  const model = new Model(config);

  return Promise.resolve()
    .then(() => runNpmAudit(config.dir))
    .then(parsedOutput =>
      reportAudit(config, parsedOutput, model.compute(parsedOutput))
    );
}

module.exports = { audit };
