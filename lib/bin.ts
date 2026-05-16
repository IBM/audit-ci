#!/usr/bin/env node
import { runAuditCi } from "./audit-ci.js";

// oxlint-disable-next-line unicorn/prefer-top-level-await
runAuditCi().catch((error) => {
  console.error(error);
  process.exit(1);
});
