/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { exec } from 'child_process';
import Report from 'npm-audit-report';
import yargs from 'yargs';

const { argv } = yargs.options({
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
}).help('help');

function w(msg) {
  process.stdout.write(msg);
}

exec('npm audit --json', (_error, stdout, stderr) => {
  if (stderr) {
    w(stderr);
    process.exitCode = 1;
  }
  const audit = JSON.parse(stdout);

  Report(audit, { reporter: 'json' }).then((reportResult) => {
    if (reportResult.exitCode) {
      w('npm-audit-report failed.\n\nExiting...\n\n');
      process.exitCode = reportResult.exitCode;
    }
    if (argv.report) {
      w(`NPM audit report JSON:\n${reportResult.report}\n\n`);
    }
    const { whitelist } = argv;
    if (whitelist.length) {
      w(`Modules to whitelist: ${whitelist.join(', ')}.\n`);
    }
    const report = JSON.parse(reportResult.report);
    const { vulnerabilities } = report.metadata;

    const failedLevels = [];
    const whitelistedFound = [];
    let failIfFindVulnerability = false;
    ['low', 'moderate', 'high', 'critical'].forEach((level) => {
      if (argv[level]) {
        failIfFindVulnerability = true;
      }
      if (vulnerabilities[level] > 0 && failIfFindVulnerability) {
        if (whitelist.length) {
          const advisories = Object.values(report.advisories);
          advisories.forEach((advisory) => {
            if (advisory.severity === level && whitelist.some(m => m === advisory.module_name)) {
              whitelistedFound.push(advisory.module_name);
            } else {
              failedLevels.push(level);
            }
          });
        } else {
          failedLevels.push(level);
        }
      }
    });

    if (whitelistedFound.length) {
      w(`Vulnerable whitelisted modules found: ${whitelistedFound.join(', ')}.\n`);
    }
    if (failedLevels.length) {
      w(`Failed to pass security audit due to ${failedLevels.join(', ')} vulnerabilities.\n\nExiting...\n\n`);
      process.exitCode = 1;
    } else {
      w('Passed NPM security audit.\n\n');
    }
  });
});
