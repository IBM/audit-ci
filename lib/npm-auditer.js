/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { runProgram } = require('./common');
const Model = require('./Model');

function reportAudit(summary, config, parsedOutput) {
  const { whitelist } = config;
  if (whitelist.length) {
    console.log(
      '\x1b[36m%s\x1b[0m',
      'Modules to whitelist: '.concat(whitelist.join(', '), '.')
    );
  }

  if (config.report) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report JSON:');
    console.log(JSON.stringify(parsedOutput, null, 2));
  }

  if (summary.whitelistedModulesFound.length) {
    const found = summary.whitelistedModulesFound.join(', ');
    const msg = `Vulnerable whitelisted modules found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }
  if (summary.whitelistedAdvisoriesFound.length) {
    const found = summary.whitelistedAdvisoriesFound.join(', ');
    const msg = `Vulnerable whitelisted advisories found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }

  if (summary.failedLevelsFound.length) {
    // Get the levels that have failed by filtering the keys with true values
    const err = `Failed security audit due to ${summary.failedLevelsFound.join(
      ', '
    )} vulnerabilities.`;
    throw new Error(err);
  }
  return summary;
}

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
