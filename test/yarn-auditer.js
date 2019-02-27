/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { expect } = require('chai');
const path = require('path');
const { audit } = require('../lib/yarn-auditer');

function config(additions) {
  return Object.assign({}, { whitelist: [], advisories: [] }, additions);
}

function testDir(s) {
  return path.resolve(__dirname, s);
}

describe('yarn-auditer', () => {
  it('reports critical severity', () => {
    return audit(
      config({
        directory: testDir('yarn-critical'),
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
        directory: testDir('yarn-critical'),
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
        directory: testDir('yarn-high'),
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
        directory: testDir('yarn-moderate'),
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
        directory: testDir('yarn-moderate'),
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
        directory: testDir('yarn-moderate'),
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
        directory: testDir('yarn-moderate'),
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
        directory: testDir('yarn-low'),
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
        directory: testDir('yarn-none'),
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
});
