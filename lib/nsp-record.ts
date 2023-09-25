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
  nspRecord: NSPRecord | GitHubNSPRecord,
): NSPContent {
  const values = Object.values(nspRecord);
  if (values.length > 0) {
    return values[0];
  }
  throw new Error(
    `Empty NSPRecord is invalid. Here's an example of a valid NSPRecord:
{
  "allowlist": [
    {
      "vulnerable-module": {
        "active": true,
        "notes": "This is a note",
        "expiry": "2022-01-01"
      }
    }
  ]
}
    `,
  );
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
  now = new Date(),
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
