const { execFile } = require('child_process');

function runProgram(command, args) {
  return new Promise(resolve =>
    execFile(
      command,
      args,
      { maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const description = command + ' ' + args.map(x => `"${x}"`).join(' ');
        resolve({ exitCode: err ? err.code : 0, stdout, stderr, description });
      }
    )
  );
}

module.exports = {
  runProgram,
};
