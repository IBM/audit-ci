/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { reportAudit, runProgram } = require('./common');
const childProcess = require('child_process');
const semver = require('semver');
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
 * Audit your NPM project!
 *
 * @param {{report: boolean, whitelist: string[], advisories: string[], levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<none>} Returns nothing on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  const { report, whitelist } = config;
  let missingLockFile = false;
  const model = new Model(config);

  return Promise.resolve().then(() => {
    const yarnVersion = getYarnVersion();
    const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
    if (!isYarnVersionSupported) {
      reject(
        Error(
          `Yarn ${yarnVersion} not supported, must be >=${MINIMUM_YARN_VERSION}`
        )
      );
    }

    if (whitelist.length) {
      console.log(`Modules to whitelist: ${whitelist.join(', ')}.`);
    }

    if (report) {
      console.log('\x1b[36m%s\x1b[0m', 'Yarn audit report JSON-lines:');
    }

    function stdoutListener(line) {
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

    function stderrListener(line) {
      const errorLine = JSON.parse(line);
      if (errorLine.type === 'error') {
        throw new Error(errorLine.data);
      }
    }
    const options = { cwd: config.dir };
    const args = ['audit', '--json'];
    return runProgram(
      'yarn',
      args,
      options,
      stdoutListener,
      stderrListener
    ).then(() => {
      if (missingLockFile) {
        console.warn(
          '\x1b[33m%s\x1b[0m',
          'No yarn.lock file. This does not affect auditing, but it may be a mistake.'
        );
      }

      const summary = model.getSummary(a => a.id);
      return reporter(summary);
    });
  });
}

module.exports = { audit };
