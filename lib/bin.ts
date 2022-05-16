#!/usr/bin/env node
import { runAuditCi } from "./audit-ci";

runAuditCi().catch((error) => {
  console.error(error);
  process.exit(1);
});
