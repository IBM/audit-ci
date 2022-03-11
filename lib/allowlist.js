/**
 * @property {string[]} modules
 * @property {number[]} advisories
 * @property {paths[]} paths
 * @export
 * @class Allowlist
 */
class Allowlist {
  /**
   *
   * @param {(string | number)[]} input the allowlisted module names, advisories, and module paths
   */
  constructor(input) {
    /** @type string[] */
    this.modules = [];
    /** @type number[] */
    this.advisories = [];
    /** @type string[] */
    this.paths = [];
    if (!input) {
      return;
    }
    input.forEach((arg) => {
      if (typeof arg === "number") {
        this.advisories.push(arg);
      } else if (arg.includes(">") || arg.includes("|")) {
        this.paths.push(arg);
      } else {
        this.modules.push(arg);
      }
    });
  }

  static mapConfigToAllowlist(config) {
    /** @type {{ allowlist: string } */
    const { allowlist } = config;
    // It's possible someone duplicated the inputs.
    // The solution is to merge into one array, change to set, and back to array.
    // This will remove duplicates.
    const set = new Set(allowlist || []);
    const input = Array.from(set);
    const obj = new Allowlist(input);
    return obj;
  }
}

module.exports = Allowlist;
