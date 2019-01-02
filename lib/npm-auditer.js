/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* eslint-disable max-len */
const childProcess = require('child_process');

function reportAudit(npmAudit, config) {
  const { levels, whitelist } = config;
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
  const whitelistedFound = [];

  Object.keys(npmAudit.advisories)
    // Get the advisories values (Object.values not supported in Node 6)
    .map(k => npmAudit.advisories[k])
    // Remove advisories that have a level that doesn't fail the build
    .filter(({ severity }) => levels[severity])
    .forEach(({ module_name: moduleName, severity }) => {
      if (whitelist.some(m => m === moduleName)) {
        whitelistedFound.push(moduleName);
      } else {
        failedLevels[severity] = true;
      }
    });

  if (whitelistedFound.length) {
    const found = whitelistedFound.join(', ');
    const msg = `Vulnerable whitelisted modules found: ${found}.`;
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
    if (stderr) {
      callback(new Error(stderr), null);
      return;
    }

    const parsedAudit = JSON.parse(stdout);
    callback(null, parsedAudit);
  });
}

/**
 * Audit your NPM project!
 *
 * @param {{report: boolean, whitelist: string[], low: boolean, moderate: boolean, high: boolean, critical: boolean}} config
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * Only the lowest vulnerability you don't want from [`low`, `moderate`, `high`, `critical`]
 * needs to be set `true`. If `moderate` is set `true` then any of
 * `moderate`, `high`, or `critical` vulnerabilities will return rejections.
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
