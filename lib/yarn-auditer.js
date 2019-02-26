/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const childProcess = require('child_process');
const semver = require('semver');
const { reportAudit, runProgram } = require('./common');
const Model = require('./Model');

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

/**
 * Audit your Yarn project!
 *
 * @param {{directory: string, report: boolean, whitelist: string[], advisories: string[], levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `directory`: the directory containing the package.json to audit.
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<any>} Returns the audit report summary on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  return Promise.resolve().then(() => {
    const { report, whitelist } = config;
    let missingLockFile = false;
    const model = new Model(config);

    const yarnVersion = getYarnVersion();
    const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
    if (!isYarnVersionSupported) {
      throw new Error(
        `Yarn ${yarnVersion} not supported, must be >=${MINIMUM_YARN_VERSION}`
      );
    }

    if (whitelist.length) {
      console.log(`Modules to whitelist: ${whitelist.join(', ')}.`);
    }

    if (report) {
      console.log('\x1b[36m%s\x1b[0m', 'Yarn audit report JSON-lines:');
    }

    function outListener(line) {
      const auditLine = JSON.parse(line);
      const { type, data } = auditLine;
      if (report) {
        console.log(JSON.stringify(auditLine, null, 2));
      }
      if (type === 'info' && data === 'No lockfile found.') {
        missingLockFile = true;
        return;
      }

      if (type !== 'auditAdvisory') {
        return;
      }

      model.process(data.advisory);
    }

    function errListener(line) {
      const errorLine = JSON.parse(line);
      if (errorLine.type === 'error') {
        throw new Error(errorLine.data);
      }
    }
    const options = { cwd: config.directory };
    const args = ['audit', '--json'];
    return runProgram('yarn', args, options, outListener, errListener).then(
      () => {
        if (missingLockFile) {
          console.warn(
            '\x1b[33m%s\x1b[0m',
            'No yarn.lock file. This does not affect auditing, but it may be a mistake.'
          );
        }

        const summary = model.getSummary(a => a.id);
        return reporter(summary, config);
      }
    );
  });
}

module.exports = { audit };
