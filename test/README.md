# Yarn Berry tests

Also, the `.yarnrc.yml` file in each Yarn Berry test project re-exports the `yarn-*.cjs` file at the root of tests.
Re-exporting the file reduces duplication and version mismatching for tests.
Currently, this project is set up to use the latest version v2.4.0 (at the time of writing this, Dec 6th, 2020).

## Intentionally-vulnerable fixtures

The fixture projects under `test/` (for example `test/npm-high`,
`test/yarn-2-moderate`, `test/pnpm-low`) **intentionally contain vulnerable
dependencies**. The test suite verifies that audit-ci correctly detects and
reports vulnerabilities at each severity level, so these fixtures must keep
depending on known-vulnerable package versions.

These fixtures are never published and never shipped to users; they only exist
so the test suite has real vulnerabilities to find. To keep Dependabot from
filing advisories against them:

- Fixture manifests are committed as `*.tmpl` templates (e.g.
  `test/npm-high/package-lock.json.tmpl`). Dependabot only recognizes exact
  manifest filenames, so templates are never scanned.
- `test/fixture-setup.ts` (wired as vitest `globalSetup`) copies every
  `*.tmpl` to its real filename before tests run, and deletes the generated
  files on teardown.
- The generated filenames are git-ignored (see `.gitignore`), so they can
  never be committed — even if a test run is interrupted before teardown.
- `dependabot.yml` additionally excludes `test/**` via `exclude-paths` as
  belt-and-braces.

Expected-output files (`npm-output.json`, `output.jsonl`, `pnpm-output.json`)
are not manifests, so they stay committed as-is and the specs' static imports
keep working. When adding a new fixture, commit its manifests with the
`.tmpl` suffix — no other step is needed.
