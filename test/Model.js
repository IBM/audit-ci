/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const { expect } = require('chai');
const Model = require('../lib/Model');

function config(additions) {
  return Object.assign({}, { whitelist: [], advisories: [] }, additions);
}

describe('Model', () => {
  it('rejects misspelled severity levels', () => {
    expect(() => new Model(config({ levels: { critical_: true } }))).to.throw(
      'Unsupported severity levels found: critical_'
    );
    expect(
      () =>
        new Model(config({ levels: { Low: true, hgih: true, mdrate: true } }))
    ).to.throw('Unsupported severity levels found: Low, hgih, mdrate');
    expect(
      () =>
        new Model(
          config({
            levels: { mdrate: true, critical: true, hgih: true, low: true },
          })
        )
    ).to.throw('Unsupported severity levels found: hgih, mdrate');
  });

  it('returns an empty summary for an empty audit output', () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      whitelist: [],
      advisories: [],
    });

    const parsedAuditOutput = {
      advisories: {},
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      whitelistedAdvisoriesNotFound: [],
      failedLevelsFound: [],
      advisoriesFound: [],
    });
  });

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

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      whitelistedAdvisoriesNotFound: [],
      failedLevelsFound: ['critical'],
      advisoriesFound: [663],
    });
  });

  it('ignores severities that are set to false', () => {
    const model = new Model({
      levels: { critical: true, low: true, high: false, moderate: false },
      whitelist: [],
      advisories: [],
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: 'A',
          module_name: 'M_A',
          severity: 'critical',
          url: 'https://A',
        },
        2: {
          id: 2,
          title: 'B',
          module_name: 'M_B',
          severity: 'low',
          url: 'https://B',
        },
        3: {
          id: 3,
          title: 'C',
          module_name: 'M_C',
          severity: 'moderate',
          url: 'https://C',
        },
        4: {
          id: 4,
          title: 'D',
          module_name: 'M_D',
          severity: 'high',
          url: 'https://D',
        },
        5: {
          id: 5,
          title: 'E',
          module_name: 'M_E',
          severity: 'critical',
          url: 'https://E',
        },
        6: {
          id: 6,
          title: 'F',
          module_name: 'M_F',
          severity: 'low',
          url: 'https://F',
        },
        7: {
          id: 7,
          title: 'G',
          module_name: 'M_G',
          severity: 'low',
          url: 'https://G',
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      whitelistedAdvisoriesNotFound: [],
      failedLevelsFound: ['critical', 'low'],
      advisoriesFound: [1, 2, 5, 6, 7],
    });
  });

  it('ignores whitelisted modules', () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      whitelist: ['M_A', 'M_D'],
      advisories: [],
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: 'A',
          module_name: 'M_A',
          severity: 'critical',
          url: 'https://A',
        },
        2: {
          id: 2,
          title: 'B',
          module_name: 'M_B',
          severity: 'low',
          url: 'https://B',
        },
        3: {
          id: 3,
          title: 'C',
          module_name: 'M_C',
          severity: 'moderate',
          url: 'https://C',
        },
        4: {
          id: 4,
          title: 'D',
          module_name: 'M_D',
          severity: 'high',
          url: 'https://D',
        },
        5: {
          id: 5,
          title: 'E',
          module_name: 'M_E',
          severity: 'critical',
          url: 'https://E',
        },
        6: {
          id: 6,
          title: 'F',
          module_name: 'M_F',
          severity: 'low',
          url: 'https://F',
        },
        7: {
          id: 7,
          title: 'G',
          module_name: 'M_G',
          severity: 'low',
          url: 'https://G',
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: ['M_A', 'M_D'],
      whitelistedAdvisoriesFound: [],
      whitelistedAdvisoriesNotFound: [],
      failedLevelsFound: ['critical', 'low', 'moderate'],
      advisoriesFound: [2, 3, 5, 6, 7],
    });
  });

  it('ignores whitelisted advisory IDs', () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      whitelist: [],
      advisories: [2, 3, 6],
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: 'A',
          module_name: 'M_A',
          severity: 'critical',
          url: 'https://A',
        },
        2: {
          id: 2,
          title: 'B',
          module_name: 'M_B',
          severity: 'low',
          url: 'https://B',
        },
        3: {
          id: 3,
          title: 'C',
          module_name: 'M_C',
          severity: 'moderate',
          url: 'https://C',
        },
        4: {
          id: 4,
          title: 'D',
          module_name: 'M_D',
          severity: 'high',
          url: 'https://D',
        },
        5: {
          id: 5,
          title: 'E',
          module_name: 'M_E',
          severity: 'critical',
          url: 'https://E',
        },
        6: {
          id: 6,
          title: 'F',
          module_name: 'M_F',
          severity: 'low',
          url: 'https://F',
        },
        7: {
          id: 7,
          title: 'G',
          module_name: 'M_G',
          severity: 'low',
          url: 'https://G',
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [2, 3, 6],
      whitelistedAdvisoriesNotFound: [],
      failedLevelsFound: ['critical', 'high', 'low'],
      advisoriesFound: [1, 4, 5, 7],
    });
  });

  it('sorts the failedLevelsFound field', () => {
    const model = new Model({
      levels: { critical: true, low: true },
      whitelist: [],
      advisories: [],
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: 'A',
          module_name: 'M_A',
          severity: 'low',
          url: 'https://A',
        },
        2: {
          id: 2,
          title: 'B',
          module_name: 'M_B',
          severity: 'critical',
          url: 'https://B',
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql({
      whitelistedModulesFound: [],
      whitelistedAdvisoriesFound: [],
      whitelistedAdvisoriesNotFound: [],
      failedLevelsFound: ['critical', 'low'],
      advisoriesFound: [1, 2],
    });
  });
});
