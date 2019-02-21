/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { runProgram, reportAudit } = require('./common');
const Model = require('./Model');

function runNpmAudit(directory) {
  const stdoutBuffer = [];
  function outListener(line) {
    stdoutBuffer.push(line);
  }

  const stderrBuffer = [];
  function errListener(line) {
    stderrBuffer.push(line);
  }

  const args = ['audit', '--json'];
  const options = { cwd: directory };
  return Promise.resolve()
    .then(() => runProgram('npm', args, options, outListener, errListener))
    .then(() => {
      if (stderrBuffer.length) {
        throw new Error(
          `Invocation of npm audit failed:\n${stderrBuffer.join('\n')}`
        );
      }

      const stdout = stdoutBuffer.join('\n');
      try {
        return JSON.parse(stdout);
      } catch (e) {
        console.log(stdout);
        throw e;
      }
    });
}

function printReport(parsedOutput, shouldReport) {
  if (shouldReport) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report JSON:');
    console.log(JSON.stringify(parsedOutput, null, 2));
  }
  return parsedOutput;
}

/**
 * Audit your NPM project!
 *
 * @param {{directory: string, report: boolean, whitelist: string[], advisories: string[], levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `directory`: the directory containing the package.json to audit.
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<any>} Returns the audit report on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  return Promise.resolve()
    .then(() => runNpmAudit(config.directory))
    .then(parsedOutput => printReport(parsedOutput, config.report))
    .then(parsedOutput =>
      reporter(new Model(config).load(parsedOutput), config, parsedOutput)
    );
}

module.exports = { audit };
