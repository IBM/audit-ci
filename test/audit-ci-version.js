const semver = require('semver');
const { auditCiVersion } = require('../lib/audit-ci-version');

// To modify what slow times are, need to use
// function() {} instead of () => {}
// eslint-disable-next-line func-names
describe('audit-ci package', function() {
  it('gets the version of the audit-ci package', () => {
    const packageVersion = auditCiVersion;
    semver.valid(packageVersion);
    semver.gte(packageVersion, '2.4.2');
  });
});
