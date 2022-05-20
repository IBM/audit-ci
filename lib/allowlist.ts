import type { GitHubAdvisoryId } from "audit-types";
import { deduplicate, isGitHubAdvisoryId } from "./common";
import type { AuditCiPreprocessedConfig } from "./config";

class Allowlist {
  modules: string[];
  advisories: GitHubAdvisoryId[];
  paths: string[];
  /**
   * @param input the allowlisted module names, advisories, and module paths
   */
  constructor(input?: string[]) {
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
      } else if (isGitHubAdvisoryId(allowlist)) {
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
    const deduplicatedAllowlist = deduplicate(allowlist || []);
    const allowlistObject = new Allowlist(deduplicatedAllowlist);
    return allowlistObject;
  }
}

export default Allowlist;
