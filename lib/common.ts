import { SpawnOptionsWithoutStdio } from "child_process";
import { spawn } from "cross-spawn";
import escapeStringRegexp from "escape-string-regexp";
import * as eventStream from "event-stream";
import * as JSONStream from "JSONStream";
import ReadlineTransform from "readline-transform";
import { blue, yellow } from "./colors";
import { AuditCiConfig } from "./config";
import { Summary } from "./model";

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

export function reportAudit(summary: Summary, config: AuditCiConfig) {
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
        `Modules to allowlist: ${allowlist.modules.join(", ")}.`
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
          `Found vulnerable allowlisted advisories: ${found}.`
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
        ", "
      )} vulnerabilities.\nVulnerable advisories are:\n${advisoriesFound
        .map((element) => gitHubAdvisoryIdToUrl(element))
        .join("\n")}`
    );
  }
  return summary;
}

export function runProgram(
  command: string,
  arguments_: readonly string[],
  options: SpawnOptionsWithoutStdio,
  stdoutListener,
  stderrListener
) {
  const transform = new ReadlineTransform({ skipEmpty: true });
  const proc = spawn(command, arguments_, options);
  proc.stdout.setEncoding("utf8");
  proc.stdout
    .pipe(transform)
    // TODO: Review this JSONStream.parse()
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    .pipe(JSONStream.parse())
    .pipe(
      eventStream.mapSync((data) => {
        if (!data) return;
        try {
          // due to response without error
          if (data.message && data.message.includes("ENOTFOUND")) {
            stderrListener(data.message);
            return;
          }
          if (data.statusCode === 404) {
            stderrListener(data.message);
            return;
          }

          stdoutListener(data);
        } catch (error) {
          stderrListener(error);
        }
      })
    );
  return new Promise<void>((resolve, reject) => {
    proc.on("close", () => resolve());
    proc.on("error", (error) => reject(error));
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

export function gitHubAdvisoryUrlToAdvisoryId(url: string) {
  return url.split("/")[4];
}

export function gitHubAdvisoryIdToUrl<T extends string>(
  id: T
): `https://github.com/advisories/${T}` {
  return `https://github.com/advisories/${id}`;
}
