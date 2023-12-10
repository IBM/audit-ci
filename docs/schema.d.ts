/* This file generates the `schema.json` file. */

import { type NSPRecord } from "../lib/nsp-record.js";

export interface Schema {
  /** @default https://github.com/IBM/audit-ci/raw/main/docs/schema.json */
  $schema?: string;

  /**
   * Prevent integration with low or higher vulnerabilities.
   *
   * @default false
   */
  low?: boolean;

  /**
   * Prevent integration with moderate or higher vulnerabilities.
   *
   * @default false
   */
  moderate?: boolean;

  /**
   * Prevent integration with high or higher vulnerabilities.
   *
   * @default false
   */
  high?: boolean;

  /**
   * Prevent integration with critical vulnerabilities.
   *
   * @default false
   */
  critical?: boolean;

  /**
   * Package manager to use for auditing.
   *
   * @default "auto"
   */
  "package-manager"?: "npm" | "yarn" | "pnpm" | "auto";

  /**
   * Vulnerable modules, advisories, and paths to allowlist from preventing integration.
   *
   * @default []
   */
  allowlist?: (string | NSPRecord)[];

  /**
   * Output format for audit-ci.
   *
   * @default "text"
   */
  "output-format"?: "json" | "text";

  /**
   * The directory containing the package.json to audit.
   *
   * @default "./"
   */
  directory?: string;

  /**
   * Pass if no audit is performed due to the registry returning ENOAUDIT.
   *
   * @default false
   */
  "pass-enoaudit"?: boolean;

  /**
   * Show allowlisted advisories that are found.
   *
   * @default true
   */
  "show-found"?: boolean;

  /**
   * Show allowlisted advisories that are not found.
   *
   * @default true
   */
  "show-not-found"?: boolean;

  /**
   * The registry to resolve packages by name and version for auditing.
   *
   * @default undefined
   */
  registry?: string;

  /**
   * The number of attempts audit-ci calls an unavailable registry before failing.
   *
   * @minimum 0
   * @maximum 50
   * @default 5
   */
  "retry-count"?: number;

  /**
   * Format for the audit report results.
   *
   * @default "important"
   */
  "report-type"?: "full" | "important" | "summary";

  /**
   * Skip auditing devDependencies.
   *
   * @default false
   */
  "skip-dev"?: boolean;

  /**
   * Extra arguments to pass to the underlying audit command.
   *
   * @default []
   */
  "extra-args"?: string[];
}
