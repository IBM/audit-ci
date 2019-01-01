/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const yargs = require('yargs');
const fs = require('fs');

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
    p: {
      alias: 'package-manager',
      default: 'auto',
      describe: 'Choose a package manager',
      choices: ['auto', 'npm', 'yarn'],
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

function mapVulnerabilityLevelInput(config) {
  if (config.l) {
    return { low: true, moderate: true, high: true, critical: true };
  }
  if (config.m) {
    return { low: false, moderate: true, high: true, critical: true };
  }
  if (config.h) {
    return { low: false, moderate: false, high: true, critical: true };
  }
  if (config.c) {
    return { low: false, moderate: false, high: false, critical: true };
  }
  return { low: false, moderate: false, high: false, critical: false };
}

argv.levels = mapVulnerabilityLevelInput(argv);

/**
 * @param {'auto' | 'npm' | 'yarn'} pmArg the package manager (including the `auto` option)
 * @returns {'npm' | 'yarn'} the non-`auto` package manager
 */
function getPackageManagerType(pmArg) {
  switch (pmArg) {
    case 'npm':
      return 'npm';
    case 'yarn':
      return 'yarn';
    case 'auto': {
      const packageLockExists = fs.existsSync('package-lock.json');
      if (packageLockExists) return 'npm';
      const shrinkwrapExists = fs.existsSync('npm-shrinkwrap.json');
      if (shrinkwrapExists) return 'npm';
      const yarnLockExists = fs.existsSync('yarn.lock');
      if (yarnLockExists) return 'yarn';
      throw Error(
        'Cannot establish package-manager type, missing package-lock.json and yarn.lock.'
      );
    }
    default:
      throw Error(`Unexpected package manager argument: ${pmArg}`);
  }
}

const pm = getPackageManagerType(argv.p);

const auditor =
  pm === 'npm' ? require('./npm-auditer') : require('./yarn-auditer');

auditor
  .audit(argv)
  .then(() => {
    console.log('\x1b[32m%s\x1b[0m', `Passed ${pm} security audit.`);
  })
  .catch(err => {
    const message = err.message || err;
    console.error('\x1b[31m%s\x1b[0m', message);
    console.error('\x1b[31m%s\x1b[0m', 'Exiting...');
    process.exitCode = 1;
  });
