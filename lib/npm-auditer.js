/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { runProgram, reportAudit } = require('./common');
const Model = require('./Model');

function runNpmAudit(dir) {
  return Promise.resolve()
    .then(() => runProgram('npm', ['audit', '--json'], dir))
    .then(({ exitCode, stdout, stderr, description }) => {
      if (stderr) {
        throw new Error(
          `Invocation of ${description} failed (exit code: ${exitCode}):\n${stderr}`
        );
      }

      try {
        return JSON.parse(stdout);
      } catch (e) {
        console.log(stdout);
        throw e;
      }
    });
}

/**
 * Audit your NPM project!
 *
 * @param {{dir: string, report: boolean, whitelist: string[], advisories: string[], levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `dir`: directory to run npm audit at.
 * `report`: whether to show the NPM audit report in the console.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * @returns {Promise<any>} Returns the audit report on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  const model = new Model(config);

  return Promise.resolve()
    .then(() => runNpmAudit(config.dir))
    .then(parsedOutput =>
      reporter(model.load(parsedOutput), config, parsedOutput)
    );
}

module.exports = { audit };
