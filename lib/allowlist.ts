import type { GitHubAdvisoryId } from "audit-types";
import { deduplicate, isGitHubAdvisoryId } from "./common";
import type { AuditCiPreprocessedConfig } from "./config";

export interface NSPContent {
  readonly active?: boolean;
  readonly notes?: string;
  readonly expiry?: Date;
}

export type NSPRecord = Record<string, NSPContent>;
export type GitHubNSPRecord = Record<GitHubAdvisoryId, NSPContent>;

export type AllowlistRecord = string | NSPRecord;

const DEFAULT_NSP_CONTENT: Readonly<NSPContent> = {
  active: true,
  notes: undefined,
  expiry: undefined,
};

class Allowlist {
  modules: NSPRecord[];
  advisories: GitHubNSPRecord[];
  paths: NSPRecord[];
  /**
   * @param input the allowlisted module names, advisories, and module paths
   */
  constructor(input?: AllowlistRecord[]) {
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

      const allowlistNspRecord =
        typeof allowlist === "string"
          ? {
              [allowlist]: DEFAULT_NSP_CONTENT,
            }
          : allowlist;

      const allowlistId =
        typeof allowlist === "string"
          ? allowlist
          : Object.keys(allowlistNspRecord)[0];

      if (allowlistId.includes(">") || allowlistId.includes("|")) {
        this.paths.push(allowlistNspRecord);
      } else if (isGitHubAdvisoryId(allowlistId)) {
        this.advisories.push(allowlistNspRecord);
      } else {
        this.modules.push(allowlistNspRecord);
      }
    }
  }

  static mapConfigToAllowlist(
    config: Pick<AuditCiPreprocessedConfig, "allowlist">
  ) {
    const { allowlist } = config;
    // const deduplicatedAllowlist = deduplicate(allowlist || []);
    const allowlistObject = new Allowlist(allowlist);
    return allowlistObject;
  }
}

export default Allowlist;
