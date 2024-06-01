import path from "path";
import { SemVer } from "semver";
import { performAuditTests } from "./yarn-auditor.js";

const version = "3.7.0";

const yarnAbsolutePath = path.resolve(__dirname, `./yarn-${version}.cjs`);

performAuditTests({
  yarnAbsolutePath,
  yarnVersion: new SemVer(version),
});
