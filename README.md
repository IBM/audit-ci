[![Build Status](https://app.travis-ci.com/IBM/audit-ci.svg?branch=main)](https://app.travis-ci.com/github/IBM/audit-ci)
[![CircleCI](https://circleci.com/gh/IBM/audit-ci/tree/main.svg?style=svg)](https://circleci.com/gh/IBM/audit-ci/tree/main)

# audit-ci

This module is intended to be consumed by your favourite continuous integration tool to
halt execution if `npm audit`, `yarn audit` or `pnpm audit` finds vulnerabilities at or above the specified
threshold while ignoring allowlisted advisories.

> Note: Use our [codemod](#codemod) to update to [`audit-ci` v6.0.0](https://github.com/IBM/audit-ci/releases/tag/v6.0.0)

## Requirements

- Node >=12.9.0 (Yarn Berry requires Node >=12.13.0)
- _(Optional)_ Yarn ^1.12.3 || Yarn >=2.4.0
- _(Optional)_ PNPM >=4.3.0

## Set up

Install `audit-ci` during your CI environment using `npx` or as a devDependency.

```sh
npx audit-ci --config ./audit-ci.jsonc
```

Alternatively, `audit-ci` can be installed as a devDependency:

```sh
# Use the option for your project's package manager
npm install -D audit-ci
yarn add -D audit-ci
pnpm install -D audit-ci
```

The next section gives examples using `audit-ci` in various CI environments.
It assumes that moderate, high, and critical severity vulnerabilities prevent build continuation.
Also, it suppresses an advisory of `axios` and a transitive advisory of `react-scripts`.

```jsonc
// audit-ci.jsonc
{
  "moderate": true,
  "allowlist": [
    // Axios denial of service https://github.com/advisories/GHSA-42xw-2xvc-qx8m
    "GHSA-42xw-2xvc-qx8m",
    // The following are for the latest create-react-app
    // https://github.com/advisories/GHSA-rp65-9cf3-cjxr
    // Alternatively, allowlist "GHSA-rp65-9cf3-cjxr" to suppress this nth-check advisory across all paths
    // or "*|react-scripts>*" to suppress advisories for all transitive dependencies of "react-scripts".
    "GHSA-rp65-9cf3-cjxr|react-scripts>@svgr/webpack>@svgr/plugin-svgo>svgo>css-select>nth-check"
  ]
}
```

### GitHub Actions

```yml
steps:
  - uses: actions/checkout@v2
  - name: Audit for vulnerabilities
    run: npx audit-ci --config ./audit-ci.jsonc
```

### CircleCI

```yml
# ... excludes set up for job
steps:
  - checkout
  - run:
      name: update-npm
      command: "sudo npm install -g npm"
  - restore_cache:
      key: dependency-cache-{{ checksum "package.json" }}
  - run:
      name: install-npm
      command: "npm install --no-audit"
  # This should run immediately after installation to reduce
  # the risk of executing a script from a compromised NPM package.
  - run:
      name: run-audit-ci
      command: npx audit-ci --config ./audit-ci.jsonc
      # If you use a pull-request-only workflow,
      # it's better to not run audit-ci on `main` and only run it on pull requests.
      # For more info: https://github.com/IBM/audit-ci/issues/69
      # For a PR-only workflow, use the below command instead of the above command:
      #
      # command: if [[ ! -z $CIRCLE_PULL_REQUEST ]] ; then audit-ci --config ./audit-ci.jsonc ; fi
```

### Travis-CI

Auditing only on PR builds is [recommended](#qa)

```yml
scripts:
  # This script should be the first that runs to reduce the risk of
  # executing a script from a compromised NPM package.
  - if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then npx audit-ci --config ./audit-ci.jsonc; fi
```

For `Travis-CI` not using PR builds:

```yml
scripts:
  - npx audit-ci --config ./audit-ci.jsonc
```

## Options

| Args | Alias             | Description                                                                                           |
| ---- | ----------------- | ----------------------------------------------------------------------------------------------------- |
| -l   | --low             | Prevents integration with low or higher vulnerabilities (default `false`)                             |
| -m   | --moderate        | Prevents integration with moderate or higher vulnerabilities (default `false`)                        |
| -h   | --high            | Prevents integration with high or critical vulnerabilities (default `false`)                          |
| -c   | --critical        | Prevents integration only with critical vulnerabilities (default `false`)                             |
| -p   | --package-manager | Choose a package manager [_choices_: `auto`, `npm`, `yarn`, `pnpm`] (default `auto`)                  |
| -a   | --allowlist       | Vulnerable modules, advisories, and paths to allowlist from preventing integration (default `none`)   |
| -o   | --output-format   | The format of the output of audit-ci [_choices_: `text`, `json`] (default `text`)                     |
| -d   | --directory       | The directory containing the package.json to audit (default `./`)                                     |
|      | --pass-enoaudit   | Pass if no audit is performed due to the registry returning ENOAUDIT (default `false`)                |
|      | --show-found      | Show allowlisted advisories that are found (default `true`)                                           |
|      | --show-not-found  | Show allowlisted advisories that are not found (default `true`)                                       |
|      | --registry        | The registry to resolve packages by name and version (default to unspecified)                         |
|      | --report-type     | Format for the audit report results [_choices_: `important`, `summary`, `full`] (default `important`) |
|      | --retry-count     | The number of attempts audit-ci calls an unavailable registry before failing (default `5`)            |
|      | --config          | Path to JSON config file                                                                              |
|      | --skip-dev        | Skip auditing devDependencies (default `false`)                                                       |

### (_Optional_) Config file specification

A config file can manage auditing preferences `audit-ci`. The config file's keys match the CLI arguments.

```txt
{
  // Only use one of ["low": true, "moderate": true, "high": true, "critical": true]
  "low": <boolean>, // [Optional] defaults `false`
  "moderate": <boolean>, // [Optional] defaults `false`
  "high": <boolean>, // [Optional] defaults `false`
  "critical": <boolean>, // [Optional] defaults `false`
  "allowlist": <string[]>, // [Optional] default `[]`
  "report-type": <string>, // [Optional] defaults `important`
  "package-manager": <string>, // [Optional] defaults `"auto"`
  "output-format": <string>, // [Optional] defaults `"text"`
  "pass-enoaudit": <boolean>, // [Optional] defaults `false`
  "show-found": <boolean>, // [Optional] defaults `true`
  "show-not-found": <boolean>, // [Optional] defaults `true`
  "registry": <string>, // [Optional] defaults `undefined`
  "retry-count": <number>, // [Optional] defaults 5
  "skip-dev": <boolean>, // [Optional] defaults `false`
}
```

Review the examples section for an [example of config file usage](#example-config-file-and-different-directory-usage).

> Refrain from using `"directory"` within the config file because `directory`
> is relative to where the command is run, rather than the directory where the config file exists.

## Examples

### Prevents build on moderate, high, or critical vulnerabilities; ignores low

```sh
npx audit-ci -m
```

### Prevents build on any vulnerability except advisory "GHSA-38f5-ghc2-fcmv" and all of lodash and base64url, don't show allowlisted

```sh
npx audit-ci -l -a "GHSA-38f5-ghc2-fcmv" lodash base64url --show-found false
```

### Prevents build with critical vulnerabilities showing the full report

```sh
audit-ci --critical --report-type full
```

### Continues build regardless of vulnerabilities, but show the summary report

```sh
npx audit-ci --report-type summary
```

### Example config file and different directory usage

#### test/npm-config-file/audit-ci.jsonc

```json
{
  "low": true,
  "package-manager": "auto",
  "allowlist": [
    "GHSA-333w-rxj3-f55r",
    "GHSA-vfvf-mqq8-rwqc",
    "example1",
    "example2",
    "GHSA-6354-6mhv-mvv5|example3",
    "GHSA-42xw-2xvc-qx8m|example4",
    "GHSA-42xw-2xvc-qx8m|example5>example4",
    "*|example6>*"
  ],
  "registry": "https://registry.npmjs.org"
}
```

```sh
npx audit-ci --directory test/npm-config-file --config test/npm-config-file/audit-ci.jsonc
```

## Codemod

```sh
npx @quinnturner/audit-ci-codemod
```

<https://github.com/quinnturner/audit-ci-codemod>

[`audit-ci` v6.0.0](https://github.com/IBM/audit-ci/releases/tag/v6.0.0) changed the identifiers used for auditing from the NPM identifiers to GitHub identifiers.
NPM identifiers are considered unstable to rely on, as they frequently change.
Meanwhile, GitHub identifiers are stable.
To accommodate for a potentially tedious migration, a codemod is available to update your configuration in-place.

```txt
$ npx @quinnturner/audit-ci-codemod
Need to install the following packages:
  @quinnturner/audit-ci-codemod
Ok to proceed? (y) y
? What's the path for the audit-ci config? audit-ci.jsonc
Performed migration from advisories, whitelist, and path-whitelist to allowlist
Performed migration from NPM advisories to GitHub advisories
```

## Q&A

### Why run `audit-ci` on PR builds for `Travis-CI` and not the push builds?

If `audit-ci` is run on the PR build and not on the push build, you can continue to push new code and create PRs parallel to the actual vulnerability fix. However, they can't be merged until the fix is implemented. Since `audit-ci` performs the audit on the PR build, it will always have the most up-to-date dependencies vs. the push build, which would require a manual merge with `main` before passing the audit.

### NPM/Yarn is returning ENOAUDIT and is breaking my build, what do I do?

The config option `--pass-enoaudit` allows passing if no audit is performed due to the registry returning ENOAUDIT. It is `false` by default to reduce the risk of merging in a vulnerable package. However, if the convenience of passing is more important for your project then you can add `--pass-enoaudit` into the CLI or add it to the config.
