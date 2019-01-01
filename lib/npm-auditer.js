/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* eslint-disable max-len */
const childProcess = require('child_process');
const reporter = require('npm-audit-report');

function reportAudit(npmAudit, config) {
  return reporter(npmAudit, { reporter: 'json' }).then(reportResult => {
    if (reportResult.exitCode) {
      const err = 'npm-audit-report failed.';
      return Promise.reject(new Error(err));
    }

    if (config.report) {
      console.log('NPM audit report JSON:');
      console.log(reportResult.report);
    }

    const { whitelist } = config;

    if (whitelist.length) {
      console.log('Modules to whitelist: '.concat(whitelist.join(', '), '.'));
    }

    const report = JSON.parse(reportResult.report);
    const { vulnerabilities } = report.metadata;
    const failedLevels = [];
    const whitelistedFound = [];
    let failIfFindVulnerability = false;
    ['low', 'moderate', 'high', 'critical'].forEach(level => {
      if (config[level]) {
        failIfFindVulnerability = true;
      }

      if (vulnerabilities[level] > 0 && failIfFindVulnerability) {
        if (whitelist.length) {
          const advisories = Object.values(report.advisories);
          advisories.forEach(advisory => {
            if (
              advisory.severity === level &&
              whitelist.some(m => m === advisory.module_name)
            ) {
              whitelistedFound.push(advisory.module_name);
            } else {
              failedLevels.push(level);
            }
          });
        } else {
          failedLevels.push(level);
        }
      }
    });

    if (whitelistedFound.length) {
      const msg = 'Vulnerable whitelisted modules found: '.concat(
        whitelistedFound.join(', '),
        '.'
      );
      console.warn(msg);
    }

    if (failedLevels.length) {
      const err = 'Failed security audit due to '.concat(
        failedLevels.join(', '),
        ' vulnerabilities.'
      );
      return Promise.reject(new Error(err));
    }
    return report;
  });
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
      reportAudit(result, config)
        .then(resolve)
        .catch(reject);
    });
  });
}

module.exports = { audit };
