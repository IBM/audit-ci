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
      throw err;
    });
  }

  return run();
}

module.exports = audit;
