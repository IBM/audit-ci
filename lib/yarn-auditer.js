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
/**
 * Change this to the appropriate version when
 * yarn audit --registry is supported:
 * @see https://github.com/yarnpkg/yarn/issues/7012
 */
const MINIMUM_YARN_AUDIT_REGISTRY_VERSION = '99.99.99';

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

function yarnAuditSupportsRegistry(yarnVersion) {
  return semver.gte(yarnVersion, MINIMUM_YARN_AUDIT_REGISTRY_VERSION);
}

/**
 * Audit your Yarn project!
 *
 * @param {{directory: string, report: { full?: boolean, summary?: boolean }, whitelist: string[], advisories: string[], registry: string, levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `directory`: the directory containing the package.json to audit.
 * `report`: report level: `full` for full report, `summary` for summary
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `registry`: the registry to resolve packages by name and version.
 * `show-not-found`: show whitelisted advisories that are not found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<any>} Returns the audit report summary on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  return Promise.resolve().then(() => {
    const { registry, report, whitelist } = config;
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

    if (report.full) {
      console.log('\x1b[36m%s\x1b[0m', 'Yarn audit report JSON:');
    }

    if (report.summary) {
      console.log('\x1b[36m%s\x1b[0m', 'Yarn audit report summary:');
    }

    function outListener(line) {
      try {
        const auditLine = JSON.parse(line);
        const { type, data } = auditLine;

        if (report.full) {
          console.log(JSON.stringify(auditLine, null, 2));
        }
        if (report.summary && type === 'auditSummary') {
          console.log(JSON.stringify(data, null, 2));
        }

        if (type === 'info' && data === 'No lockfile found.') {
          missingLockFile = true;
          return;
        }

        if (type !== 'auditAdvisory') {
          return;
        }

        model.process(data.advisory);
      } catch (err) {
        console.error(
          '\x1b[31m%s\x1b[0m',
          `ERROR: Cannot JSON.parse response:`
        );
        console.error(line);
        throw err;
      }
    }

    function errListener(line) {
      const errorLine = JSON.parse(line);
      if (errorLine.type === 'error') {
        throw new Error(errorLine.data);
      }
    }
    const options = { cwd: config.directory };
    const args = ['audit', '--json'];
    if (registry) {
      const auditRegistrySupported = yarnAuditSupportsRegistry(yarnVersion);
      if (auditRegistrySupported) {
        args.push('--registry', registry);
      } else {
        console.warn(
          '\x1b[33m%s\x1b[0m',
          'Yarn audit does not support the registry flag yet.'
        );
      }
    }
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
