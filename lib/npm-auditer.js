/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { auditCiVersion } = require('./audit-ci-version');
const { runProgram, reportAudit } = require('./common');
const Model = require('./Model');

function runNpmAudit(config) {
  const { directory, registry, _npm } = config;
  const npmExec = _npm || 'npm';

  let stdoutBuffer = {};
  function outListener(data) {
    stdoutBuffer = Object.assign({}, stdoutBuffer, data);
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
    .then(() => runProgram(npmExec, args, options, outListener, errListener))
    .then(() => {
      if (stderrBuffer.length) {
        throw new Error(
          `Invocation of npm audit failed:\n${stderrBuffer.join('\n')}`
        );
      }

      return stdoutBuffer;
    });
}

function printReport(parsedOutput, levels, reportType) {
  function printReportObj(text, obj) {
    console.log('\x1b[36m%s\x1b[0m', text);
    console.log(JSON.stringify(obj, null, 2));
  }

  console.log(`audit-ci version: ${auditCiVersion}`);

  switch (reportType) {
    case 'full':
      printReportObj('Yarn audit report JSON:', parsedOutput);
      break;
    case 'important': {
      const relevantAdvisories = Object.keys(parsedOutput.advisories).reduce(
        (acc, advisory) =>
          levels[parsedOutput.advisories[advisory].severity]
            ? Object.assign(
                { [advisory]: parsedOutput.advisories[advisory] },
                acc
              )
            : acc,
        {}
      );
      const keyFindings = {
        advisories: relevantAdvisories,
        metadata: parsedOutput.metadata,
      };
      printReportObj('NPM audit report results:', keyFindings);
      break;
    }
    case 'summary':
      printReportObj('NPM audit report summary:', parsedOutput.metadata);
      break;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }
  return parsedOutput;
}

/**
 * Audit your NPM project!
 *
 * @param {{directory: string, report: { full?: boolean, summary?: boolean }, whitelist: string[], advisories: string[], registry: string, levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `directory`: the directory containing the package.json to audit.
 * `report-type`: [`important`, `summary`, `full`] how the audit report is displayed.
 * `whitelist`: a list of packages that should not break the build if their vulnerability is found.
 * `advisories`: a list of advisory ids that should not break the build if found.
 * `registry`: the registry to resolve packages by name and version.
 * `show-not-found`: show whitelisted advisories that are not found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * `_npm`: a path to npm, uses npm from PATH if not specified.
 * @returns {Promise<any>} Returns the audit report summary on resolve, `Error` on rejection.
 */
function audit(config, reporter = reportAudit) {
  return Promise.resolve()
    .then(() => runNpmAudit(config))
    .then(parsedOutput => {
      if (parsedOutput.error) {
        const { code, summary } = parsedOutput.error;

        if (code !== 'ENOAUDIT' || !config['pass-enoaudit']) {
          throw new Error(`code ${code}: ${summary}`);
        }
      }
      return printReport(parsedOutput, config.levels, config['report-type']);
    })
    .then(parsedOutput =>
      reporter(new Model(config).load(parsedOutput), config, parsedOutput)
    );
}

module.exports = { audit };
