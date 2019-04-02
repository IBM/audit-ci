/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const yargs = require('yargs');
const fs = require('fs');
const path = require('path');

const { argv } = yargs
  .config('config')
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
      default: false,
      describe: 'Show a full audit report',
      type: 'boolean',
    },
    s: {
      alias: 'summary',
      default: true,
      describe: 'Show a summary audit report',
      type: 'boolean',
    },
    a: {
      alias: 'advisories',
      default: [],
      describe: 'Whitelisted advisory ids',
      type: 'array',
    },
    w: {
      alias: 'whitelist',
      default: [],
      describe: 'Whitelisted module names',
      type: 'array',
    },
    d: {
      alias: 'directory',
      default: './',
      describe: 'The directory containing the package.json to audit',
      type: 'string',
    },
    'show-not-found': {
      default: true,
      describe: 'Show whitelisted advisories that are not found',
      type: 'boolean',
    },
    registry: {
      default: undefined,
      describe: 'The registry to resolve packages by name and version',
      type: 'string',
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

function mapReportLevelInput(config) {
  if (config.r) {
    return { full: true };
  }
  if (config.s) {
    return { summary: true };
  }
  return {};
}

argv.levels = mapVulnerabilityLevelInput(argv);
argv.report = mapReportLevelInput(argv);

/**
 * @param {'auto' | 'npm' | 'yarn'} pmArg the package manager (including the `auto` option)
 * @param {string} directory the directory where the package manager files exist
 * @returns {'npm' | 'yarn'} the non-`auto` package manager
 */
function getPackageManagerType(pmArg, directory) {
  switch (pmArg) {
    case 'npm':
      return 'npm';
    case 'yarn':
      return 'yarn';
    case 'auto': {
      const getPath = file => path.resolve(directory, file);
      const packageLockExists = fs.existsSync(getPath('package-lock.json'));
      if (packageLockExists) return 'npm';
      const shrinkwrapExists = fs.existsSync(getPath('npm-shrinkwrap.json'));
      if (shrinkwrapExists) return 'npm';
      const yarnLockExists = fs.existsSync(getPath('yarn.lock'));
      if (yarnLockExists) return 'yarn';
      throw Error(
        'Cannot establish package-manager type, missing package-lock.json and yarn.lock.'
      );
    }
    default:
      throw Error(`Unexpected package manager argument: ${pmArg}`);
  }
}

const pm = getPackageManagerType(argv.p, argv.d);

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
