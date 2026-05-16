import path from "node:path";
import url from "node:url";
import { SemVer } from "semver";
import { performAuditTests } from "./yarn-auditor.js";

const version = "1.22.19";

const yarnAbsolutePath = path.resolve(
  path.dirname(url.fileURLToPath(import.meta.url)),
  `./yarn-${version}.cjs`,
);

performAuditTests({ yarnAbsolutePath, yarnVersion: new SemVer(version) });
