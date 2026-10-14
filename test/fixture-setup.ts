/**
 * Vitest global setup: materialize test fixture manifests.
 *
 * The fixture projects under test/ intentionally depend on known-vulnerable
 * package versions so the suite can verify vulnerability detection. To keep
 * Dependabot from filing advisories against them, the manifests are committed
 * as `*.tmpl` templates (filenames Dependabot does not recognize) and copied
 * to their real filenames here, before any test file runs. The generated
 * files are git-ignored and removed again on teardown, so they can never be
 * committed or scanned.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TEMPLATE_SUFFIX = ".tmpl";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));

async function* findTemplates(
  directory: string
): AsyncGenerator<string> {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* findTemplates(fullPath);
    } else if (entry.isFile() && entry.name.endsWith(TEMPLATE_SUFFIX)) {
      yield fullPath;
    }
  }
}

function targetOf(templatePath: string): string {
  return templatePath.slice(0, -TEMPLATE_SUFFIX.length);
}

export default async function setup(): Promise<() => Promise<void>> {
  const generated: string[] = [];
  for await (const templatePath of findTemplates(testDirectory)) {
    const targetPath = targetOf(templatePath);
    await fs.copyFile(templatePath, targetPath);
    generated.push(targetPath);
  }
  return async function teardown(): Promise<void> {
    await Promise.all(generated.map((p) => fs.rm(p, { force: true })));
  };
}
