/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const childProcess = require('child_process');

function reportAudit(npmAudit, config) {
  const { advisories, levels, whitelist } = config;
  if (whitelist.length) {
    console.log(
      '\x1b[36m%s\x1b[0m',
      'Modules to whitelist: '.concat(whitelist.join(', '), '.')
    );
  }

  if (config.report) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report JSON:');
    console.log(JSON.stringify(npmAudit, null, 2));
  }

  const failedLevels = {
    low: false,
    moderate: false,
    high: false,
    critical: false,
  };
  const whitelistedModulesFound = [];
  const whitelistedAdvisoriesFound = [];

  Object.keys(npmAudit.advisories)
    // Get the advisories values (Object.values not supported in Node 6)
    .map(k => npmAudit.advisories[k])
    // Remove advisories that have a level that doesn't fail the build
    .filter(({ severity }) => levels[severity])
    .forEach(({ id, module_name: moduleName, severity }) => {
      if (whitelist.some(m => m === moduleName)) {
        whitelistedModulesFound.push(moduleName);
      } else if (advisories.some(a => +a === id)) {
        whitelistedAdvisoriesFound.push(id);
      } else {
        failedLevels[severity] = true;
      }
    });

  if (whitelistedModulesFound.length) {
    const found = whitelistedModulesFound.join(', ');
    const msg = `Vulnerable whitelisted modules found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }
  if (whitelistedAdvisoriesFound.length) {
    const found = whitelistedAdvisoriesFound.join(', ');
    const msg = `Vulnerable whitelisted advisories found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }

  // Get the levels that have failed by filtering the keys with true values
  const failedLevelsFound = Object.keys(failedLevels)
    .filter(l => failedLevels[l])
    .join(', ');
  // If any of the levels have been failed
  if (failedLevelsFound) {
    // Get the levels that have failed by filtering the keys with true values
    const err = `Failed security audit due to ${failedLevelsFound} vulnerabilities.`;
    throw new Error(err);
  }
  return npmAudit;
}

function runNpmAudit(callback) {
  childProcess.exec('npm audit --json', (_error, stdout, stderr) => {
    if (stdout) {
      try {
        const parsedAudit = JSON.parse(stdout);
        callback(null, parsedAudit);
        return;
      } catch (error) {
        callback(new Error('Invalid output'), null);
        return;
      }
    }

    if (_error) {
      callback(new Error(stderr), null);
    }
  });
}

/**
 * Audit your NPM project!
 *
 * @param {{report: boolean, whitelist: string[], advisories: string[], levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<any>} Returns the audit report on resolve, `Error` on rejection.
 */
function audit(config) {
  return new Promise((resolve, reject) => {
    runNpmAudit((err, result) => {
      if (err) {
        reject(err);
        return;
      }
      try {
        const report = reportAudit(result, config);
        resolve(report);
      } catch (error) {
        reject(error);
      }
    });
  });
}

module.exports = { audit };
