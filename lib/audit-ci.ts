#!/usr/bin/env node
import audit from "./audit";
import { printAuditCiVersion } from "./audit-ci-version";
import { green, red } from "./colors";
import { runYargs } from "./config";

async function main() {
  const argv = await runYargs();

  printAuditCiVersion(argv.o);

  const { p: packageManager, o: outputFormat } = argv;

  try {
    await audit(packageManager, argv);
    if (outputFormat === "text") {
      console.log(green, `Passed ${packageManager} security audit.`);
    }
  } catch (error: any) {
    if (outputFormat === "text") {
      const message = error.message || error;
      console.error(red, message);
      console.error(red, "Exiting...");
    }
    process.exitCode = 1;
  }
}

main();
