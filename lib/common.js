const { spawn } = require('child_process');
const byline = require('byline');

// function runProgram(command, args, dir) {
//   const options = {
//     maxBuffer: 10 * 1024 * 1024,
//     cwd: dir || undefined,
//   };

//   return new Promise(resolve =>
//     execFile(command, args, options, (err, stdout, stderr) => {
//       const description = command + ' ' + args.map(x => `"${x}"`).join(' ');
//       resolve({ exitCode: err ? err.code : 0, stdout, stderr, description });
//     })
//   );
// }

function reportAudit(summary, config, parsedOutput) {
  const { whitelist } = config;
  if (whitelist.length) {
    console.log(
      '\x1b[36m%s\x1b[0m',
      'Modules to whitelist: '.concat(whitelist.join(', '), '.')
    );
  }

  if (config.report) {
    console.log('\x1b[36m%s\x1b[0m', 'NPM audit report JSON:');
    console.log(JSON.stringify(parsedOutput, null, 2));
  }

  if (summary.whitelistedModulesFound.length) {
    const found = summary.whitelistedModulesFound.join(', ');
    const msg = `Vulnerable whitelisted modules found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }
  if (summary.whitelistedAdvisoriesFound.length) {
    const found = summary.whitelistedAdvisoriesFound.join(', ');
    const msg = `Vulnerable whitelisted advisories found: ${found}.`;
    console.warn('\x1b[33m%s\x1b[0m', msg);
  }

  if (summary.failedLevelsFound.length) {
    // Get the levels that have failed by filtering the keys with true values
    const err = `Failed security audit due to ${summary.failedLevelsFound.join(
      ', '
    )} vulnerabilities.`;
    throw new Error(err);
  }
  return summary;
}

function listenTo(stream, reject, listener) {
  stream.setEncoding('utf8');
  const linedStream = byline.createStream(stream);
  linedStream.on('readable', () => {
    while (true) {
      let line = linedStream.read();
      if (line === null) {
        break;
      }

      try {
        listener(line);
      } catch (e) {
        reject(e);
      }
    }
  });
}

function runProgram(command, args, options, stdoutListener, stderrListener) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, options);

    listenTo(proc.stdout, reject, stdoutListener);
    listenTo(proc.stderr, reject, stderrListener);
    proc.on('close', () => resolve());
  });
}

module.exports = {
  runProgram,
  reportAudit,
};
