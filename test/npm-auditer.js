/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { expect } = require('chai');
const path = require('path');
const { audit } = require('../lib/npm-auditer');

function config(additions) {
  const defaultConfig = {
    levels: {
      low: false,
      moderate: false,
      high: false,
      critical: false,
    },
    report: {},
    advisories: [],
    whitelist: [],
    directory: './',
    registry: undefined,
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
  it('reports critical severity', () => {
    return audit(
      config({
        directory: testDir('npm-critical'),
        levels: { critical: true },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
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
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  it('reports high severity', () => {
    return audit(
      config({
        directory: testDir('npm-high'),
        levels: { high: true },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        failedLevelsFound: ['high'],
        advisoriesFound: [690],
      });
    });
  });
  it('reports moderate severity', () => {
    return audit(
      config({
        directory: testDir('npm-moderate'),
        levels: { moderate: true },
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
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
        failedLevelsFound: [],
        advisoriesFound: [],
      });
    });
  });
  // eslint-disable-next-line func-names
  it('fails with error code ETIMEDOUT on an invalid site', function(cb) {
    this.slow(25000);
    audit(
      config({
        directory: testDir('npm-low'),
        levels: { low: true },
        registry: 'https://registry.npmjs.co',
      })
    ).catch(err => {
      expect(err.message).to.include('code ETIMEDOUT');
      cb();
    });
  });
  it('fails errors with code ENOAUDIT on a valid site with no audit', cb => {
    audit(
      config({
        directory: testDir('npm-low'),
        levels: { low: true },
        registry: 'https://example.com',
      })
    ).catch(err => {
      expect(err.message).to.include('code ENOAUDIT');
      cb();
    });
  });
});
