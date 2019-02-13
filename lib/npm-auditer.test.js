const { expect } = require('chai');
const { audit } = require('./npm-auditer');
const path = require('path');

function config(additions) {
  return Object.assign({}, { whitelist: [], advisories: [] }, additions);
}

// expect(async () => ....).to.throw() does not work, we use this function instead.
async function err(f) {
  try {
    await f();
    return null;
  } catch (e) {
    return e.message;
  }
}

function testDir(s) {
  return path.resolve(__dirname, '../test', s);
}

describe('npm-auditer', () => {
  it('rejects misspelled severity levels', async () => {
    expect(
      await err(() => audit(config({ levels: { critical_: true } })))
    ).to.equal('Unsupported severity levels found: critical_');
    expect(
      await err(() =>
        audit(config({ levels: { Low: true, hgih: true, mdrate: true } }))
      )
    ).to.equal('Unsupported severity levels found: Low, hgih, mdrate');
    expect(
      await err(() =>
        audit(
          config({
            levels: { mdrate: true, critical: true, hgih: true, low: true },
          })
        )
      )
    ).to.equal('Unsupported severity levels found: hgih, mdrate');
  });

  it('reports critical severity', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-critical'),
        levels: { critical: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['critical'],
      advisoriesFound: [663],
    });
  });
  it('does not report critical severity if it set to false', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-critical'),
        levels: { critical: false },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: [],
      advisoriesFound: [],
    });
  });
  it('reports high severity', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-high'),
        levels: { high: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['high'],
      advisoriesFound: [690],
    });
  });
  it('reports moderate severity', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-moderate'),
        levels: { moderate: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['moderate'],
      advisoriesFound: [658],
    });
  });
  it('does not report moderate severity if it set to false', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-moderate'),
        levels: { moderate: false },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: [],
      advisoriesFound: [],
    });
  });
  it('ignores an advisory if it is whitelisted', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-moderate'),
        levels: { moderate: true },
        advisories: [658],
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [658],
      failedLevelsFound: [],
      advisoriesFound: [],
    });
  });
  it('does not ignore an advisory that is not whitelisted', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-moderate'),
        levels: { moderate: true },
        advisories: [659],
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['moderate'],
      advisoriesFound: [658],
    });
  });
  it('reports low severity', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-low'),
        levels: { low: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['low'],
      advisoriesFound: [577],
    });
  });
  it('none', async () => {
    const summary = await audit(
      config({
        dir: testDir('npm-none'),
        levels: { low: true },
      }),
      summary => summary
    );
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: [],
      advisoriesFound: [],
    });
  });
});
