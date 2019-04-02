/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { runProgram, reportAudit } = require('./common');
const Model = require('./Model');

function runNpmAudit(config) {
  const { directory, registry } = config;

  const stdoutBuffer = [];
  function outListener(line) {
    stdoutBuffer.push(line);
  }

  const stderrBuffer = [];
  function errListener(line) {
    stderrBuffer.push(line);
  }

  const args = ['audit', '--json'];
  if (registry) {
    args.push('--registry', registry);
  }
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
        console.error(stdout);
        throw e;
      }
    });
}

function printReport(parsedOutput, report) {
  if (report.full) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report JSON:');
    console.log(JSON.stringify(parsedOutput, null, 2));
  }
  if (report.summary) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report summary:');
    console.log(JSON.stringify(parsedOutput.metadata, null, 2));
  }
  return parsedOutput;
}

/**
 * Audit your NPM project!
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
  return Promise.resolve()
    .then(() => runNpmAudit(config))
    .then(parsedOutput => printReport(parsedOutput, config.report))
    .then(parsedOutput =>
      reporter(new Model(config).load(parsedOutput), config, parsedOutput)
    );
}

module.exports = { audit };
