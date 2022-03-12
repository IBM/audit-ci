import { AuditCiPreprocessedConfig } from "./config";

class Allowlist {
  modules: string[];
  advisories: string[];
  paths: string[];
  /**
   * @param input the allowlisted module names, advisories, and module paths
   */
  constructor(input: string[]) {
    this.modules = [];
    this.advisories = [];
    this.paths = [];
    if (!input) {
      return;
    }
    for (const allowlist of input) {
      if (typeof allowlist === "number") {
        throw new TypeError(
          "Unsupported number as allowlist. Perform codemod to update config to use GitHub advisory as identifiers: https://github.com/quinnturner/audit-ci-codemod with `npx @quinnturner/audit-ci-codemod`. See also: https://github.com/IBM/audit-ci/pull/217"
        );
      }

      if (allowlist.includes(">") || allowlist.includes("|")) {
        this.paths.push(allowlist);
      } else if (allowlist.startsWith("GHSA")) {
        this.advisories.push(allowlist);
      } else {
        this.modules.push(allowlist);
      }
    }
  }

  static mapConfigToAllowlist(
    config: Pick<AuditCiPreprocessedConfig, "allowlist">
  ) {
    const { allowlist } = config;
    // It's possible someone duplicated the inputs.
    // The solution is to merge into one array, change to set, and back to array.
    // This will remove duplicates.
    const set = new Set(allowlist || []);
    const input = [...set];
    const allowlistObject = new Allowlist(input);
    return allowlistObject;
  }
}

export default Allowlist;
