const { expect } = require('chai');
const { audit } = require('./npm-auditer');
const path = require('path');

describe('a', () => {
  it('b', async () => {
    const d = await audit({
      __dir: path.resolve(__dirname, '../test/npm-high'),
      whitelist: [],
      advisories: [],
      levels: { high: true },
    });
    console.log(JSON.stringify(d, 0, 2));
    expect(d).to.eql('_');
  });
});
