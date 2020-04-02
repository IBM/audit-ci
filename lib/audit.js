const npmAuditer = require("./npm-auditer");
const yarnAuditer = require("./yarn-auditer");

function audit(pm, config, reporter) {
  const auditor = pm === "npm" ? npmAuditer : yarnAuditer;
  const PARTIAL_RETRY_ERROR_MSG = {
    // The three ENOAUDIT error messages for NPM are:
    // `Either your login credentials are invalid or your registry (${opts.registry}) does not support audit.`
    // `Your configured registry (${opts.registry}) does not support audit requests.`
    // `Your configured registry (${opts.registry}) may not support audit requests, or the audit endpoint may be temporarily unavailable.`
    // Between them, all three use the phrasing 'not support audit'.
    npm: `not support audit`,
    yarn: "503 Service Unavailable",
  };

  function run(attempt = 0) {
    return auditor.audit(config, reporter).catch((err) => {
      const message = err.message || err;
      if (
        attempt < config["retry-count"] &&
        message &&
        message.includes(PARTIAL_RETRY_ERROR_MSG[pm])
      ) {
        console.log("RETRY-RETRY");
        return run(attempt + 1);
      }
      if (
        config["pass-enoaudit"] &&
        message.includes(PARTIAL_RETRY_ERROR_MSG[pm])
      ) {
        console.warn(
          "\x1b[33m%s\x1b[0m",
          `ACTION RECOMMENDED: An audit could not performed due to ${config["retry-count"]} audits that resulted in ENOAUDIT. Perform an audit manually and verify that no significant vulnerabilities exist before merging.`
        );
        return Promise.resolve();
      }
      throw err;
    });
  }

  return run();
}

module.exports = audit;
