// Rather than have a bunch of yarn-berry.cjs of different versions,
// we can specify a single yarn-berry.cjs and require the file for each package.
module.exports = require("../../../yarn-berry.cjs");
