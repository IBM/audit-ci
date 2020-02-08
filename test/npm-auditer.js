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
describe('npm-auditer', function testNpmAuditer() {
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
        whitelistedPathsFound: [],
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
        whitelistedPathsFound: [],
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
        whitelistedPathsFound: [],
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
        whitelistedPathsFound: [],
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
        whitelistedPathsFound: [],
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
        whitelistedPathsFound: [],
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
        whitelistedPathsFound: [],
        failedLevelsFound: ['moderate'],
        advisoriesFound: [658],
      });
    });
  });
  it('reports only vulnerabilities with a not whitelisted path', () => {
    return audit(
      config({
        directory: testDir('npm-whitelisted-path'),
        levels: { moderate: true },
        'path-whitelist': ['880|github-build>axios'],
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: ['880|github-build>axios'],
        failedLevelsFound: ['moderate'],
        advisoriesFound: [880],
      });
    });
  });
  it('whitelist all vulnerabilities with a whitelisted path', () => {
    return audit(
      config({
        directory: testDir('npm-whitelisted-path'),
        levels: { moderate: true },
        'path-whitelist': ['880|axios', '880|github-build>axios'],
      }),
      summary => summary
    ).then(summary => {
      expect(summary).to.eql({
        whitelistedModulesFound: [],
        whitelistedAdvisoriesFound: [],
        whitelistedAdvisoriesNotFound: [],
        whitelistedPathsFound: ['880|axios', '880|github-build>axios'],
        failedLevelsFound: [],
        advisoriesFound: [],
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
        whitelistedPathsFound: [],
        failedLevelsFound: ['low'],
        advisoriesFound: [722],
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
        whitelistedPathsFound: [],
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
  // it('passes using --pass-enoaudit', () => {
  //   const directory = testDir('npm-500');
  //   return audit(
  //     config({
  //       directory,
  //       'pass-enoaudit': true,
  //       _npm: path.join(directory, 'npm'),
  //     })
  //   );
  // });
});
