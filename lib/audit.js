const npmAuditer = require('./npm-auditer');
const yarnAuditer = require('./yarn-auditer');

function audit(pm, config, reporter) {
  const auditor = pm === 'npm' ? npmAuditer : yarnAuditer;

  const RETRY_ERROR_MSG = {
    npm: `${
      config.registry
        ? `npm ERR! audit Your configured registry (${config.registry}) `
        : ''
    }does not support audit requests.`,
    yarn: '503 Service Unavailable',
  };

  function run(attempt = 0) {
    return auditor.audit(config, reporter).catch(err => {
      const message = err.message || err;
      if (
        attempt < config['retry-count'] &&
        message &&
        message.includes(RETRY_ERROR_MSG[pm])
      ) {
        console.log('RETRY-RETRY');
        return run(attempt + 1);
      }
      if (config['pass-enoaudit']) {
        return Promise.resolve().then(() => {
          console.warn(
            '\x1b[33m%s\x1b[0m',
            `ACTION RECOMMENDED: An audit could not performed due to ${
              config['retry-count']
            } audits that resulted in ENOAUDIT. Perform an audit manually and verify that no significant vulnerabilities exist before merging.`
          );
        });
      }
      throw err;
    });
  }

  return run();
}

module.exports = audit;
