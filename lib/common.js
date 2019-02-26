/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { spawn } = require('cross-spawn');
const byline = require('byline');

function reportAudit(summary, config) {
  const { whitelist } = config;
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

  if (summary.failedLevelsFound.length) {
    // Get the levels that have failed by filtering the keys with true values
    const err = `Failed security audit due to ${summary.failedLevelsFound.join(
      ', '
    )} vulnerabilities.`;
    throw new Error(err);
  }
  return summary;
}

function listenTo(stream, reject, listener) {
  stream.setEncoding('utf8');
  const linedStream = byline.createStream(stream);
  linedStream.on('readable', () => {
    for (;;) {
      const line = linedStream.read();
      if (line === null) {
        break;
      }

      try {
        listener(line);
      } catch (e) {
        reject(e);
      }
    }
  });
}

function runProgram(command, args, options, stdoutListener, stderrListener) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, options);

    listenTo(proc.stdout, reject, stdoutListener);
    listenTo(proc.stderr, reject, stderrListener);
    proc.on('close', () => resolve());
  });
}

module.exports = {
  runProgram,
  reportAudit,
};
