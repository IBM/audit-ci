import type { GitHubAdvisoryId } from "audit-types";
import { isGitHubAdvisoryId } from "./common.js";
import {
  type NSPContent,
  type NSPRecord,
  type GitHubNSPRecord,
  getAllowlistId,
  isNSPRecordActive,
} from "./nsp-record.js";

export type AllowlistRecord = string | NSPRecord;

const DEFAULT_NSP_CONTENT: Readonly<NSPContent> = {
  active: true,
  notes: undefined,
  expiry: undefined,
};

/**
 * Takes a string and converts it into a NSPRecord object. If a NSPRecord
 * is passed in, no modifications are made and the record is returned as is.
 *
 * @param recordOrId A string or NSPRecord object.
 * @returns Normalized NSPRecord object.
 */
export function normalizeAllowlistRecord(
  recordOrId: AllowlistRecord,
): NSPRecord {
  return typeof recordOrId === "string"
    ? {
        [recordOrId]: DEFAULT_NSP_CONTENT,
      }
    : recordOrId;
}

/**
 * Removes duplicate allowlist items from an array based on the allowlist id.
 *
 * @param recordsOrIds An array containing allowlist string ids or NSPRecords.
 * @returns An array of NSPRecords with duplicates removed.
 */
export function dedupeAllowlistRecords(
  recordsOrIds: AllowlistRecord[],
): NSPRecord[] {
  const map = new Map<string, NSPRecord>();
  for (const recordOrId of recordsOrIds) {
    const nspRecord = normalizeAllowlistRecord(recordOrId);
    const advisoryId = getAllowlistId(nspRecord);

    if (!map.has(advisoryId)) {
      map.set(advisoryId, nspRecord);
    }
  }

  return [...map.values()];
}

class Allowlist {
  modules: string[];
  advisories: GitHubAdvisoryId[];
  paths: string[];
  moduleRecords: NSPRecord[];
  advisoryRecords: GitHubNSPRecord[];
  pathRecords: NSPRecord[];
  /**
   * @param input the allowlisted module names, advisories, and module paths
   */
  constructor(input?: AllowlistRecord[]) {
    this.modules = [];
    this.advisories = [];
    this.paths = [];
    this.moduleRecords = [];
    this.advisoryRecords = [];
    this.pathRecords = [];
    if (!input) {
      return;
    }
    for (const allowlist of input) {
      if (typeof allowlist === "number") {
        throw new TypeError(
          "Unsupported number as allowlist. Perform codemod to update config to use GitHub advisory as identifiers: https://github.com/quinnturner/audit-ci-codemod with `npx @quinnturner/audit-ci-codemod`. See also: https://github.com/IBM/audit-ci/pull/217",
        );
      }

      const allowlistNspRecord = normalizeAllowlistRecord(allowlist);
      if (!isNSPRecordActive(allowlistNspRecord)) {
        continue;
      }

      const allowlistId =
        typeof allowlist === "string"
          ? allowlist
          : getAllowlistId(allowlistNspRecord);

      if (allowlistId.includes(">") || allowlistId.includes("|")) {
        this.paths.push(allowlistId);
        this.pathRecords.push(allowlistNspRecord);
      } else if (isGitHubAdvisoryId(allowlistId)) {
        this.advisories.push(allowlistId);
        this.advisoryRecords.push(allowlistNspRecord);
      } else {
        this.modules.push(allowlistId);
        this.moduleRecords.push(allowlistNspRecord);
      }
    }
  }

  static mapConfigToAllowlist(
    config: Readonly<{ allowlist: AllowlistRecord[] }>,
  ) {
    const { allowlist } = config;
    const deduplicatedAllowlist = dedupeAllowlistRecords(allowlist || []);
    const allowlistObject = new Allowlist(deduplicatedAllowlist);
    return allowlistObject;
  }
}

export default Allowlist;
