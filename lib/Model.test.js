const { expect } = require('chai');
const Model = require('./Model');

function config(additions) {
  return Object.assign({}, { whitelist: [], advisories: [] }, additions);
}

describe.only('Model', () => {
  it('compute a summary', () => {
    const model = new Model({
      levels: { critical: true },
      whitelist: [],
      advisories: [],
    });

    const parsedAuditOutput = {
      advisories: {
        '663': {
          id: 663,
          title: 'Command Injection',
          module_name: 'open',
          severity: 'critical',
          url: 'https://npmjs.com/advisories/663',
        },
      },
    };

    const summary = model.compute(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      failedLevelsFound: ['critical'],
      advisoriesFound: [663],
    });
  });
});
