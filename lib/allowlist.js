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
   * @param {string[]} input the allowlisted module names, advisories, and module paths
   */
  constructor(input) {
    /** @type string[] */
    this.modules = [];
    /** @type string[] */
    this.advisories = [];
    /** @type string[] */
    this.paths = [];
    if (!input) {
      return;
    }
    input.forEach((arg) => {
      if (typeof arg === "number") {
        throw new Error(
          "Unsupported number as allowlist. Perform codemod to update config to use GitHub advisory as identifiers: https://github.com/quinnturner/audit-ci-codemod with `npx @quinnturner/audit-ci-codemod`. See also: https://github.com/IBM/audit-ci/pull/217"
        );
      }

      if (arg.includes(">") || arg.includes("|")) {
        this.paths.push(arg);
      } else if (arg.startsWith("GHSA")) {
        this.advisories.push(arg);
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
