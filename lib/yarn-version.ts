import { execSync } from "child_process";
import semver from "semver";

export const MINIMUM_YARN_CLASSIC_VERSION = "1.12.3";
export const MINIMUM_YARN_BERRY_VERSION = "2.4.0";
/**
 * Change this to the appropriate version when
 * yarn audit --registry is supported:
 * @see https://github.com/yarnpkg/yarn/issues/7012
 */
const MINIMUM_YARN_AUDIT_REGISTRY_VERSION = "99.99.99";

export function yarnSupportsClassicAudit(yarnVersion: string | semver.SemVer) {
  return semver.satisfies(yarnVersion, `^${MINIMUM_YARN_CLASSIC_VERSION}`);
}

export function yarnSupportsBerryAudit(yarnVersion: string | semver.SemVer) {
  return semver.gte(yarnVersion, MINIMUM_YARN_BERRY_VERSION);
}

export function yarnSupportsAudit(yarnVersion: string | semver.SemVer) {
  return (
    yarnSupportsClassicAudit(yarnVersion) || yarnSupportsBerryAudit(yarnVersion)
  );
}

export function yarnAuditSupportsRegistry(yarnVersion: string | semver.SemVer) {
  return semver.gte(yarnVersion, MINIMUM_YARN_AUDIT_REGISTRY_VERSION);
}

const versionMap = new Map<string, string>();
export function getYarnVersion(yarnExec = "yarn", cwd?: string) {
  const key = `${yarnExec}:${cwd}`;
  let version = versionMap.get(key);
  if (version) return version;
  version = execSync(`${yarnExec} -v`, { cwd }).toString().replace("\n", "");
  versionMap.set(key, version);
  return version;
}
