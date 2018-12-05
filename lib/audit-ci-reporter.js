/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const childProcess = require('child_process');
const reporter = require('npm-audit-report');

/**
 * @param {object} npmAudit The NPM audit
 * @param {{report: boolean, whitelist: string[],
 * low: boolean, moderate: boolean, high: boolean, critical: boolean}} config
 * @throws
 */
function reportAudit(npmAudit, config) {
  return reporter(npmAudit, { reporter: 'json' }).then((reportResult) => {
    if (reportResult.exitCode) {
      const err = 'npm-audit-report failed.\n\nExiting...\n\n';
      return Promise.reject(new Error(err));
    }

    if (config.report) {
      process.stdout.write(
        'NPM audit report JSON:\n'.concat(reportResult.report, '\n\n'),
      );
    }

    const { whitelist } = config;

    if (whitelist.length) {
      process.stdout.write(
        'Modules to whitelist: '.concat(whitelist.join(', '), '.\n'),
      );
    }

    const report = JSON.parse(reportResult.report);
    const { vulnerabilities } = report.metadata;
    const failedLevels = [];
    const whitelistedFound = [];
    let failIfFindVulnerability = false;
    ['low', 'moderate', 'high', 'critical'].forEach((level) => {
      if (config[level]) {
        failIfFindVulnerability = true;
      }

      if (vulnerabilities[level] > 0 && failIfFindVulnerability) {
        if (whitelist.length) {
          const advisories = Object.values(report.advisories);
          advisories.forEach((advisory) => {
            if (
              advisory.severity === level
              && whitelist.some(m => m === advisory.module_name)
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
        '.\n',
      );
      process.stdout.write(msg);
    }

    if (failedLevels.length) {
      const err = 'Failed to pass security audit due to '.concat(
        failedLevels.join(', '),
        ' vulnerabilities.\n\nExiting...\n\n',
      );
      return Promise.reject(new Error(err));
    }

    process.stdout.write('Passed NPM security audit.\n\n');
    return report;
  });
}

/**
 * Runs NPM audit and provides the callback with the audit
 * @param {function(string?, object):void} callback arg0: stderr, arg1: audit
 */
function runNpmAudit(callback) {
  childProcess.exec('npm audit --json', (_error, stdout, stderr) => {
    if (stderr) {
      callback(stderr, null);
    }

    const parsedAudit = JSON.parse(stdout);
    callback(null, parsedAudit);
  });
}

function audit(config) {
  return new Promise((resolve, reject) => {
    runNpmAudit((err, result) => {
      if (err) {
        reject(err);
      }
      reportAudit(result, config)
        .then(report => resolve(report))
        .catch(error => reject(error));
    });
  });
}

module.exports = { audit };
