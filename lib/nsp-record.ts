import type { GitHubAdvisoryId } from "audit-types";

export interface NSPContent {
  readonly active?: boolean;
  readonly notes?: string;
  readonly expiry?: string | number;
}

export type NSPRecord = Record<string, NSPContent>;
export type GitHubNSPRecord = Record<GitHubAdvisoryId, NSPContent>;

/**
 * Retrieves the allowlist id from the NSPRecord.
 *
 * @param nspRecord NSPRecord object.
 * @returns The advisory id.
 */
export function getAllowlistId(nspRecord: NSPRecord | GitHubNSPRecord): string {
  return Object.keys(nspRecord)[0];
}

/**
 * Retrieves the content for the NSPRecord.
 *
 * @param nspRecord NSPRecord object.
 * @returns The NSPContent object.
 */
export function getNSPContent(
  nspRecord: NSPRecord | GitHubNSPRecord
): NSPContent {
  return Object.values(nspRecord)[0];
}

/**
 * Determines if the NSPRecord is active.
 *
 * @param nspRecord NSPRecord object.
 * @param now The current date. The default is initialized to the current date.
 * @returns True if the record is active, false otherwise.
 */
export function isNSPRecordActive(
  nspRecord: NSPRecord,
  now = new Date()
): boolean {
  const content = getNSPContent(nspRecord);
  if (!content.active) {
    return false;
  }

  if (content.expiry) {
    const expiryDate = new Date(content.expiry);
    if (expiryDate.getTime() > 0) {
      // Expiry is valid, check if we've passed it yet.
      return now.getTime() < expiryDate.getTime();
    }

    // Expiry isn't valid. For safety, disable the rule.
    return false;
  }

  return true;
}
