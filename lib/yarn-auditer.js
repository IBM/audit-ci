/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

const childProcess = require('child_process');
const spawn = require('cross-spawn');
const semver = require('semver');

const MINIMUM_YARN_VERSION = '1.12.3';

function getYarnVersion() {
  const version = childProcess
    .execSync('yarn -v')
    .toString()
    .replace('\n', '');
  return version;
}

function yarnSupportsAudit(yarnVersion) {
  return semver.gte(yarnVersion, MINIMUM_YARN_VERSION);
}

// Yarn uses a JSON-line format for audits.
// Rather than running a single exec and post-processing the result,
// we audit each line sequentially. This reduces memory consumption.
function runAndReportYarnAudit(config) {
  return new Promise((resolve, reject) => {
    const yarnVersion = getYarnVersion();
    const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
    if (!isYarnVersionSupported) {
      reject(
        Error(
          `Yarn ${yarnVersion} not supported, must be >=${MINIMUM_YARN_VERSION}`
        )
      );
    }

    const jsonLinesResults = [];
    const proc = spawn('yarn', ['audit', '--json']);

    const { levels, report, whitelist } = config;
    if (whitelist.length) {
      console.log(`Modules to whitelist: ${whitelist.join(', ')}.`);
    }

    if (report) {
      console.log('\x1b[36m%s\x1b[0m', 'Yarn audit report JSON-lines:');
    }
    const failedLevels = {
      low: false,
      moderate: false,
      high: false,
      critical: false,
    };
    const whitelistedFound = [];
    let missingLockFile = false;

    proc.stdout.setEncoding('utf8');
    proc.stdout.on('data', jsonl => {
      /** @type {{ type: string, data: any }} */
      const auditLine = JSON.parse(jsonl);
      const { type, data } = auditLine;
      if (report) {
        console.log(JSON.stringify(auditLine, null, 2));
      }
      if (type === 'auditAdvisory') {
        const { module_name: moduleName, severity } = data.advisory;
        if (levels[severity]) {
          if (whitelist.some(m => m === moduleName)) {
            whitelistedFound.push(moduleName);
          } else {
            failedLevels[severity] = true;
          }
        }
      } else if (type === 'info' && data === 'No lockfile found.') {
        missingLockFile = true;
      }
    });
    proc.stderr.setEncoding('utf8');
    proc.stderr.on('data', jsonl => {
      /** @type {{ type: string, data: any }} */
      const errorLine = JSON.parse(jsonl);
      if (errorLine.type === 'error') {
        reject(Error(errorLine.data));
      }
    });
    proc.on('close', () => {
      if (missingLockFile) {
        console.warn(
          '\x1b[33m%s\x1b[0m',
          'No yarn.lock file. This does not affect auditing, but it may be a mistake.'
        );
      }
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
        const err = `Failed security audit due to ${failedLevelsFound} vulnerabilities.`;
        reject(Error(err));
      } else {
        resolve(jsonLinesResults);
      }
    });
  });
}

function audit(config) {
  return runAndReportYarnAudit(config);
}

module.exports = { audit };
