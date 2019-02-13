const { expect } = require('chai');
const { audit } = require('./npm-auditer');
const path = require('path');

function config(additions) {
  return Object.assign({}, { whitelist: [], advisories: [] }, additions);
}

describe('npm-auditer', () => {
  it('catches critical severity', async () => {
    const summary = await audit(
      config({
        dir: path.resolve(__dirname, '../test/npm-critical'),
        levels: { critical: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['critical'],
    });
  });
  it('catches high severity', async () => {
    const summary = await audit(
      config({
        dir: path.resolve(__dirname, '../test/npm-high'),
        levels: { high: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['high'],
    });
  });
  it('catches moderate severity', async () => {
    const summary = await audit(
      config({
        dir: path.resolve(__dirname, '../test/npm-moderate'),
        levels: { moderate: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['moderate'],
    });
  });
  it('catches low severity', async () => {
    const summary = await audit(
      config({
        dir: path.resolve(__dirname, '../test/npm-low'),
        levels: { low: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['low'],
    });
  });
  it('none', async () => {
    const summary = await audit(
      config({
        dir: path.resolve(__dirname, '../test/npm-none'),
        levels: { low: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: [],
    });
  });
});
