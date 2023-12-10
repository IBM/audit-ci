import { GitHubAdvisoryId } from "audit-types";
import { SpawnOptionsWithoutStdio } from "child_process";
import { spawn } from "cross-spawn";
import escapeStringRegexp from "escape-string-regexp";
import eventStream from "event-stream";
import * as JSONStream from "jsonstream-next";
import ReadlineTransform from "readline-transform";
import Allowlist from "./allowlist.js";
import { blue, yellow } from "./colors.js";
import { AuditCiConfig } from "./config.js";
import { Summary } from "./model.js";

export function partition<T>(a: T[], fun: (parameter: T) => boolean) {
  const returnValue: { truthy: T[]; falsy: T[] } = { truthy: [], falsy: [] };
  for (const item of a) {
    if (fun(item)) {
      returnValue.truthy.push(item);
    } else {
      returnValue.falsy.push(item);
    }
  }
  return returnValue;
}

export type ReportConfig = Pick<
  AuditCiConfig,
  "show-found" | "show-not-found" | "output-format"
> & { allowlist: Allowlist };

export function reportAudit(summary: Summary, config: ReportConfig) {
  const {
    allowlist,
    "show-not-found": showNotFound,
    "show-found": showFound,
    "output-format": outputFormat,
  } = config;
  const {
    allowlistedModulesFound,
    allowlistedAdvisoriesFound,
    allowlistedModulesNotFound,
    allowlistedAdvisoriesNotFound,
    allowlistedPathsNotFound,
    failedLevelsFound,
    advisoriesFound,
    advisoryPathsFound,
  } = summary;

  if (outputFormat === "text") {
    if (allowlist.modules.length > 0) {
      console.log(
        blue,
        `Modules to allowlist: ${allowlist.modules.join(", ")}.`,
      );
    }

    if (showFound) {
      if (allowlistedModulesFound.length > 0) {
        const found = allowlistedModulesFound.join(", ");
        console.warn(yellow, `Found vulnerable allowlisted modules: ${found}.`);
      }
      if (allowlistedAdvisoriesFound.length > 0) {
        const found = allowlistedAdvisoriesFound.join(", ");
        console.warn(
          yellow,
          `Found vulnerable allowlisted advisories: ${found}.`,
        );
      }
    }
    if (showNotFound) {
      if (allowlistedModulesNotFound.length > 0) {
        const found = allowlistedModulesNotFound
          .sort((a, b) => a.localeCompare(b))
          .join(", ");
        const allowlistMessage =
          allowlistedModulesNotFound.length === 1
            ? `Consider not allowlisting module: ${found}.`
            : `Consider not allowlisting modules: ${found}.`;
        console.warn(yellow, allowlistMessage);
      }
      if (allowlistedAdvisoriesNotFound.length > 0) {
        const found = allowlistedAdvisoriesNotFound
          .sort((a, b) => a.localeCompare(b))
          .join(", ");
        const allowlistMessage =
          allowlistedAdvisoriesNotFound.length === 1
            ? `Consider not allowlisting advisory: ${found}.`
            : `Consider not allowlisting advisories: ${found}.`;
        console.warn(yellow, allowlistMessage);
      }
      if (allowlistedPathsNotFound.length > 0) {
        const found = allowlistedPathsNotFound
          .sort((a, b) => a.localeCompare(b))
          .join(", ");
        const allowlistMessage =
          allowlistedPathsNotFound.length === 1
            ? `Consider not allowlisting path: ${found}.`
            : `Consider not allowlisting paths: ${found}.`;
        console.warn(yellow, allowlistMessage);
      }
    }

    if (advisoryPathsFound.length > 0) {
      const found = advisoryPathsFound.join("\n");
      console.warn(yellow, `Found vulnerable advisory paths:`);
      console.log(found);
    }
  }

  if (failedLevelsFound.length > 0) {
    // Get the levels that have failed by filtering the keys with true values
    throw new Error(
      `Failed security audit due to ${failedLevelsFound.join(
        ", ",
      )} vulnerabilities.\nVulnerable advisories are:\n${advisoriesFound
        .map((element) => gitHubAdvisoryIdToUrl(element))
        .join("\n")}`,
    );
  }
  return summary;
}

function hasMessage(value: unknown): value is { message: unknown } {
  return typeof value === "object" && value != undefined && "message" in value;
}

function hasStatusCode(
  value: unknown,
): value is { statusCode: unknown; message: unknown } {
  return (
    typeof value === "object" && value != undefined && "statusCode" in value
  );
}

export function runProgram(
  command: string,
  arguments_: readonly string[],
  options: SpawnOptionsWithoutStdio,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  stdoutListener: (data: any) => void,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  stderrListener: (data: any) => void,
) {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const transform = new ReadlineTransform({ skipEmpty: true });
  const proc = spawn(command, arguments_, options);
  let recentMessage: string;
  let errorMessage: string;
  proc.stdout.setEncoding("utf8");
  proc.stdout
    .pipe(
      transform.on("error", (error: unknown) => {
        throw error;
      }),
    )
    .pipe(
      eventStream.mapSync((data: string) => {
        recentMessage = data;
        return data;
      }),
    )
    .pipe(
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error -- JSONStream.parse() accepts (pattern: any) when it should accept (pattern?: any)
      JSONStream.parse().on("error", () => {
        errorMessage = recentMessage;
        throw new Error(errorMessage);
      }),
    )
    .pipe(
      eventStream.mapSync((data: unknown) => {
        if (!data) return;
        try {
          // due to response without error
          if (
            hasMessage(data) &&
            typeof data.message === "string" &&
            data.message.includes("ENOTFOUND")
          ) {
            stderrListener(data.message);
            return;
          }
          // TODO: There are no tests that cover this case, not sure when this happens.
          if (hasStatusCode(data) && data.statusCode === 404) {
            stderrListener(data.message);
            return;
          }

          stdoutListener(data);
        } catch (error) {
          stderrListener(error);
        }
      }),
    );
  return new Promise<void>((resolve, reject) => {
    proc.on("close", () => {
      if (errorMessage) {
        return reject(new Error(errorMessage));
      }
      return resolve();
    });
    proc.on("error", (error) =>
      reject(errorMessage ? new Error(errorMessage) : error),
    );
  });
}

function wildcardToRegex(stringWithWildcard: string) {
  const regexString = stringWithWildcard
    .split(/\*+/) // split at every wildcard (*) character
    .map((s) => escapeStringRegexp(s)) // escape the substrings to make sure that they aren't evaluated
    .join(".*"); // construct a regex matching anything at each wildcard location
  return new RegExp(`^${regexString}$`);
}

export function matchString(template: string, string_: string) {
  return template.includes("*")
    ? wildcardToRegex(template).test(string_)
    : template === string_;
}

export function isGitHubAdvisoryId(id: unknown): id is GitHubAdvisoryId {
  return typeof id === "string" && id.startsWith("GHSA");
}

export function gitHubAdvisoryUrlToAdvisoryId(url: string): GitHubAdvisoryId {
  return url.split("/")[4] as GitHubAdvisoryId;
}

export function gitHubAdvisoryIdToUrl<T extends string>(
  id: T,
): `https://github.com/advisories/${T}` {
  return `https://github.com/advisories/${id}`;
}

export function deduplicate(array: readonly string[]) {
  return [...new Set(array)];
}
