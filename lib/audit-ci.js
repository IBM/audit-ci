/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const yargs = require('yargs');
const auditor = require('./audit-ci-reporter');

const { argv } = yargs
  .options({
    l: {
      alias: 'low',
      default: false,
      describe: 'Exit for low vulnerabilities or higher',
      type: 'boolean',
    },
    m: {
      alias: 'moderate',
      default: false,
      describe: 'Exit for moderate vulnerabilities or higher',
      type: 'boolean',
    },
    h: {
      alias: 'high',
      default: false,
      describe: 'Exit for high vulnerabilities or higher',
      type: 'boolean',
    },
    c: {
      alias: 'critical',
      default: false,
      describe: 'Exit for critical vulnerabilities',
      type: 'boolean',
    },
    r: {
      alias: 'report',
      default: true,
      describe: 'Show NPM audit report',
      type: 'boolean',
    },
    w: {
      alias: 'whitelist',
      default: [],
      describe: 'Whitelisted vulnerabilities',
      type: 'array',
    },
  })
  .help('help');

auditor
  .audit(argv)
  .then(() => {
    console.log('\x1b[32m%s\x1b[0m', 'Passed NPM security audit.');
  })
  .catch((err) => {
    if (err) {
      const message = err.message || 'An unknown error occurred.';
      console.error('\x1b[31m%s\x1b[0m', message);
      console.error('\x1b[31m%s\x1b[0m', 'Exiting...');
      process.exitCode = 1;
    }
  });
