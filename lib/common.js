/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { spawn } = require('cross-spawn');
const eventStream = require('event-stream');
const JSONStream = require('JSONStream');
const ReadlineTransform = require('readline-transform');

function reportAudit(summary, config) {
  const { whitelist, 'show-not-found': showNotFound } = config;
  if (whitelist.length) {
    console.log(
      '\x1b[36m%s\x1b[0m',
      'Modules to whitelist: '.concat(whitelist.join(', '), '.')
    );
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
  if (showNotFound && summary.whitelistedAdvisoriesNotFound.length) {
    const found = summary.whitelistedAdvisoriesNotFound.join(', ');
    const msg = `Vulnerable whitelisted advisories not found: ${found}.\nConsider not whitelisting them.`;
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

function runProgram(command, args, options, stdoutListener, stderrListener) {
  return new Promise(resolve => {
    const proc = spawn(command, args, options);
    const transform = new ReadlineTransform({ skipEmpty: true });

    proc.stdout.setEncoding('utf8');
    proc.stdout
      .pipe(transform)
      .pipe(JSONStream.parse())
      .pipe(
        eventStream.mapSync(data => {
          if (!data) return;
          try {
            stdoutListener(data);
          } catch (error) {
            stderrListener(error);
          }
        })
      );
    proc.on('close', () => resolve());
  });
}

module.exports = {
  runProgram,
  reportAudit,
};
