/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { expect } = require('chai');
const path = require('path');
// const { audit } = require('../lib/npm-auditer');
const audit = require('../lib/audit').bind(null, 'npm');

function config(additions) {
  const defaultConfig = {
    levels: {
      low: false,
      moderate: false,
      high: false,
      critical: false,
    },
    'report-type': 'important',
    advisories: [],
    whitelist: [],
    'show-not-found': false,
    'retry-count': 5,
    directory: './',
    registry: undefined,
    'pass-enoaudit': false,
  };
  return Object.assign({}, defaultConfig, additions);
}

function testDir(s) {
  return path.resolve(__dirname, s);
}

// To modify what slow times are, need to use
// function() {} instead of () => {}
// eslint-disable-next-line func-names
describe('npm-auditer', function() {
  this.slow(6000);
  it('prints full report with critical severity', () => {
    return audit(
      config({
        directory: testDir('npm-critical'),
        levels: { critical: true },
        'report-type': 'full',
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: ['critical'],
        advisoriesFound: [663],
      });
    });
  });
  it('does not report critical severity if it set to false', () => {
    return audit(
      config({
        directory: testDir('npm-critical'),
        levels: { critical: false },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it('reports summary with high severity', () => {
    return audit(
      config({
        directory: testDir('npm-high'),
        levels: { high: true },
        'report-type': 'summary',
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: ['high'],
        advisoriesFound: [690],
      });
    });
  });
  it('reports important info with moderate severity', () => {
    return audit(
      config({
        directory: testDir('npm-moderate'),
        levels: { moderate: true },
        'report-type': 'important',
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: ['moderate'],
        advisoriesFound: [658],
      });
    });
  });
  it('does not report moderate severity if it set to false', () => {
    return audit(
      config({
        directory: testDir('npm-moderate'),
        levels: { moderate: false },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it('ignores an advisory if it is whitelisted', () => {
    return audit(
      config({
        directory: testDir('npm-moderate'),
        levels: { moderate: true },
        advisories: [658],
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [658],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it('does not ignore an advisory that is not whitelisted', () => {
    return audit(
      config({
        directory: testDir('npm-moderate'),
        levels: { moderate: true },
        advisories: [659],
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [659],
        failedLevelsFound: ['moderate'],
        advisoriesFound: [658],
      });
    });
  });
  it('reports low severity', () => {
    return audit(
      config({
        directory: testDir('npm-low'),
        levels: { low: true },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: ['low'],
        advisoriesFound: [577],
      });
    });
  });
  it('passes with no vulnerabilities', () => {
    return audit(
      config({
        directory: testDir('npm-none'),
        levels: { low: true },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it('fails with error code ENOTFOUND on a non-existent site', done => {
    audit(
      config({
        directory: testDir('npm-low'),
        levels: { low: true },
        registry: 'https://registry.nonexistentdomain0000000000.com',
      })
    ).catch(err => {
      expect(err.message).to.include('code ENOTFOUND');
      done();
    });
  });
  it('fails errors with code ENOAUDIT on a valid site with no audit', done => {
    audit(
      config({
        directory: testDir('npm-low'),
        levels: { low: true },
        registry: 'https://example.com',
      })
    ).catch(err => {
      expect(err.message).to.include('code ENOAUDIT');
      done();
    });
  });
  it('passes using --pass-enoaudit', () => {
    const directory = testDir('npm-500');
    return audit(
      config({
        directory,
        'pass-enoaudit': true,
        _npm: path.join(directory, 'npm'),
      })
    );
  });
});
