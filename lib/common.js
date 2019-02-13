const { execFile } = require('child_process');

function runProgram(command, args, dir) {
  const options = {
    maxBuffer: 10 * 1024 * 1024,
    cwd: dir || undefined,
  };

  return new Promise(resolve =>
    execFile(command, args, options, (err, stdout, stderr) => {
      const description = command + ' ' + args.map(x => `"${x}"`).join(' ');
      resolve({ exitCode: err ? err.code : 0, stdout, stderr, description });
    })
  );
}

module.exports = {
  runProgram,
};
