# Yarn Berry tests

When creating Yarn Berry tests, there are several files and folders that may generate that are not necessary for auditing using `yarn npm audit --all --recursive --json`.

- .pnp.js

- .yarn/cache

Consider manually deleting them before committing.

Also, the `.yarn/releases/yarn-berry.cjs` file in each project re-exports the `yarn-berry.cjs` file at the root of tests.
Re-exporting the file reduces duplication and version mismatching for tests.
Currently, this project is set up to use the latest version v2.4.0 (at the time of writing this, Dec 6th, 2020).
