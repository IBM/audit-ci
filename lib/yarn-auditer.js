/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { reportAudit } = require('./common');
const childProcess = require('child_process');
const spawn = require('cross-spawn');
const semver = require('semver');
const Model = require('./Model');
const byline = require('byline');

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

function run(command, args, options, stdoutListener, stderrListener) {
  return new Promise(resolve => {
    const proc = spawn(command, args, options);

    proc.stdout.setEncoding('utf8');
    const linedStdout = byline.createStream(proc.stdout);

    linedStdout.on('readable', () => {
      while (true) {
        let line = linedStdout.read();
        if (line === null) {
          break;
        }

        stdoutListener(line);
      }
    });

    proc.stderr.setEncoding('utf8');
    const linedStderr = byline.createStream(proc.stderr);
    linedStderr.on('readable', () => {
      while (true) {
        let line = linedStderr.read();
        if (line === null) {
          break;
        }

        stderrListener(line);
      }
    });

    proc.on('close', () => resolve());
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
 * @returns {Promise<none>} Returns nothing on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  const { report, whitelist } = config;
  const model = new Model(config);
  let bufferedOutput = '';
  return Promise.resolve()
    .then(() => {
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
        bufferedOutput += line + '\n';
      }
      function stderrListener(line) {
        const errorLine = JSON.parse(line);
        if (errorLine.type === 'error') {
          throw new Error(errorLine.data);
        }
      }
      return run(
        'yarn',
        ['audit', '--json'],
        { cwd: config.dir },
        stdoutListener,
        stderrListener
      );
    })
    .then(() => onClose(bufferedOutput, report, model, reporter));
}

function onClose(bufferedOutput, report, model, reporter) {
  let missingLockFile = false;

  bufferedOutput
    .split('\n')
    .filter(line => line.trim().length > 0)
    .forEach(jsonBlob => {
      const auditLine = JSON.parse(jsonBlob);
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
    });

  if (missingLockFile) {
    console.warn(
      '\x1b[33m%s\x1b[0m',
      'No yarn.lock file. This does not affect auditing, but it may be a mistake.'
    );
  }

  const summary = model.getSummary(a => a.id);
  reporter(summary);
  return summary;
}

module.exports = { audit };
