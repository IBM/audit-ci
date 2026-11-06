#!/usr/bin/env node
import { runAuditCi } from "./audit-ci.js";

runAuditCi().catch((error) => {
  console.error(error);
  process.exit(1);
});
