# Yarn Berry tests

Also, the `.yarnrc.yml` file in each Yarn Berry test project re-exports the `yarn-*.cjs` file at the root of tests.
Re-exporting the file reduces duplication and version mismatching for tests.
Currently, this project is set up to use the latest version v2.4.0 (at the time of writing this, Dec 6th, 2020).
