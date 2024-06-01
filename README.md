# audit-ci

[![npm version](https://badge.fury.io/js/audit-ci.svg)](https://badge.fury.io/js/audit-ci)
[![CircleCI](https://circleci.com/gh/IBM/audit-ci/tree/main.svg?style=svg)](https://circleci.com/gh/IBM/audit-ci/tree/main)
[![GitHub CI](https://github.com/IBM/audit-ci/actions/workflows/build.yml/badge.svg)](https://github.com/IBM/audit-ci/actions/workflows/build.yml)
[![CodeQL](https://github.com/IBM/audit-ci/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/IBM/audit-ci/actions/workflows/codeql-analysis.yml)

This module is intended to be consumed by your favourite continuous integration tool to
halt execution if `npm audit`, `yarn audit`, or `pnpm audit` finds vulnerabilities at or above the specified
threshold while ignoring allowlisted advisories.

> Note: Use our [codemod](#codemod) to update to [`audit-ci` v6.0.0](https://github.com/IBM/audit-ci/releases/tag/v6.0.0)

## Requirements

- Node >=16
- _(Optional)_ Yarn ^1.12.3 || Yarn >=2.4.0 && <4.0.0
- _(Optional)_ PNPM >=4.3.0
- _(Optional)_ Bun

## Limitations

- Yarn Classic workspaces does not audit `devDependencies`. See [this issue](https://github.com/yarnpkg/yarn/issues/7047) for more information.
- Yarn v4 is not supported because it provides similar functionality to `audit-ci`.
  For more information, see the [documentation on `yarn npm audit`](https://yarnpkg.com/cli/npm/audit#options).
  If you'd like `audit-ci` to support Yarn v4, voice your opinion on [this issue](https://github.com/IBM/audit-ci/issues/332).
- Bun is supported by exporting the `bun.lockb` into a Yarn v1 `yarn.lock` file.
  Accordingly, auditing a `bun.lockb` file with `audit-ci` requires Yarn v1.

## Set up

_(Recommended)_ Install `audit-ci` during your CI environment using `npx`, `yarn dlx`, or `pnpm dlx` immediately after checking out the project's repository.

```sh
# Use the option for your project's package manager, pinning to a major version to avoid breaking changes
npx audit-ci@^7 --config ./audit-ci.jsonc
yarn dlx audit-ci@^7 --config ./audit-ci.jsonc
pnpm dlx audit-ci@^7 --config ./audit-ci.jsonc
```

Alternatively, `audit-ci` can be installed as a devDependency.
The downside of this approach is that the CI may run a `postinstall` script of a compromised package before running `audit-ci`.

```sh
# Use the option for your project's package manager
npm install -D audit-ci
yarn add -D audit-ci
pnpm install -D audit-ci
bun install -D audit-ci
```

The next section gives examples using `audit-ci` in various CI environments.
It assumes moderate, high, and critical severity vulnerabilities prevent build continuation.
Also, it suppresses an advisory of `axios` and a transitive advisory of `react-scripts`.

```jsonc
// audit-ci.jsonc
{
  // $schema provides code completion hints to IDEs.
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  "moderate": true,
  "allowlist": [
    // Axios denial of service https://github.com/advisories/GHSA-42xw-2xvc-qx8m
    "GHSA-42xw-2xvc-qx8m",
    // The following are for the latest create-react-app
    // https://github.com/advisories/GHSA-rp65-9cf3-cjxr
    // Alternatively, allowlist "GHSA-rp65-9cf3-cjxr" to suppress this nth-check advisory across all paths
    // or "*|react-scripts>*" to suppress advisories for all transitive dependencies of "react-scripts".
    "GHSA-rp65-9cf3-cjxr|react-scripts>@svgr/webpack>@svgr/plugin-svgo>svgo>css-select>nth-check",
  ],
}
```

### Bun

Bun supports exporting the `bun.lockb` into a Yarn v1 `yarn.lock` file.

```sh
bun install -y
```

Afterwards, you can run `audit-ci` with the `yarn` package manager.

### Allowlisting

Allowlists are a mechanism to suppress an advisory warning from the audit. A team may want to suppress an advisory when:

- A fix has already been started
- There is no bandwidth to fix the advisory
- The risk is tolerable for the project
- The advisory is inaccurate or incorrect
- The vulnerable code is not actually used

An allowlist may contain multiple allowlist records. There are three categories of allowlist record formats:

- `module` allowlist record (example: `axios`, suppresses all advisories _directly_ caused by `axios`, **not transitive advisories**)
- `advisory` allowlist record (example: `GHSA-42xw-2xvc-qx8m`, suppresses all instances of advisory based on the GitHub advisory identifier)
- `path` allowlist record (example: `GHSA-rp65-9cf3-cjxr|react-scripts>@svgr/webpack>@svgr/plugin-svgo>svgo>css-select>nth-check`, the specific and full advisory path **with wildcard support**)

When `audit-ci` identifies new advisories at or above the configured level, the CI pipeline will fail.

```txt
Found vulnerable advisory paths:
GHSA-pw2r-vq6v-hr8c|axios>follow-redirects
GHSA-74fj-2j2h-c42q|axios>follow-redirects
GHSA-4w2v-q235-vp99|axios
GHSA-42xw-2xvc-qx8m|axios
GHSA-cph5-m8f7-6c5x|axios
Failed security audit due to high, moderate vulnerabilities.
Vulnerable advisories are:
https://github.com/advisories/GHSA-pw2r-vq6v-hr8c
https://github.com/advisories/GHSA-74fj-2j2h-c42q
https://github.com/advisories/GHSA-4w2v-q235-vp99
https://github.com/advisories/GHSA-42xw-2xvc-qx8m
https://github.com/advisories/GHSA-cph5-m8f7-6c5x
Exiting...
```

Advisories can be suppressed using several approaches. Each approach is useful in unique scenarios.

First, the most granular and secure approach, using paths. If in the future the same advisory arises with a different path, the pipeline will fail.

```jsonc
"allowlist": [
  "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
  "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
  "GHSA-4w2v-q235-vp99|axios",
  "GHSA-42xw-2xvc-qx8m|axios",
  "GHSA-cph5-m8f7-6c5x|axios"
]
```

The next best approach is suppressing the advisories using advisory IDs. This approach may be useful if your team knows that the application is not (and will not be) affected by the advisory regardless of the path. Often, the same advisory can be present in many paths. Allowlisting by advisory ID is terser than the alternative of listing all paths.

```jsonc
"allowlist": [
  "GHSA-pw2r-vq6v-hr8c",
  "GHSA-74fj-2j2h-c42q",
  "GHSA-4w2v-q235-vp99",
  "GHSA-42xw-2xvc-qx8m",
  "GHSA-cph5-m8f7-6c5x"
]
```

The next approach is to allowlist the modules themselves. All current and future advisories are automatically suppressed when using module allowlist records. Compared to other suppression approaches, there's an increased risk of a new advisory impacting your application due to the broad suppression. Suppressing via a module allowlist record is often less useful than using path allowlist records + wildcards, as noted in the final approach.

```jsonc
"allowlist": [
  "axios",
  "follow-redirects"
]
```

Finally, wildcards can be used within path allowlist records. Wildcards are useful for trusted development-only dependencies such as `react-scripts`. Unlike the module allowlist record of `react-scripts`, the path allowlist of `*|react-scripts>*` suppresses transitive dependency advisories (dependencies of dependencies).

Wildcard matching works by:

1. splitting the allowlist record at every wildcard
1. constructing a regex matching anything at each wildcard location

An allowlist record may include any number of wildcards such as `*|react-scripts>*>*>example>*`.

#### Allowlist Formats

The simplest way to add an advisory to the allowlist is using a string:

```jsonc
"allowlist": [
  "axios"
]
```

You can also use an object notation ([NSPRecord](#nsprecord-fields)) in which you can add notes and control the expiration of this exception:

```jsonc
"allowlist": [
  {
    "axios": {
      "active": true,
      "notes": "Ignore this until November 20th",
      "expiry": "20 November 2022 11:00"
    }
  }
]
```

`allowlist` supports both formats at the same time, so feel free to mix and match:

```jsonc
"allowlist": [
  {
    "axios": {
      "active": true,
      "notes": "Ignore this until November 20th",
      "expiry": "20 November 2022 11:00"
    }
  },
  "base64url"
]
```

#### NSPRecord Fields

| Attribute | Type             | Description                                               | Example                                                                                                                                                                                                                                                                                                                      |
| --------- | ---------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `active`  | boolean          | Whether the exception is active or not                    | `true`                                                                                                                                                                                                                                                                                                                       |
| `expiry`  | string \| number | Human-readable date, or milliseconds since the UNIX Epoch | - `'2020-01-31'` <br> - `'2020/01/31'` <br> - `'01/31/2021, 11:03:58'` <br> - `'1 March 2016 15:00'` <br> - `'1 March 2016 3:00 pm'` <br> - `'2012-01-26T13:51:50.417-07:00'` <br> - `'Sun, 11 Jul 2021 03:03:13 GMT'` <br> - `'Thu Jan 26 2017 11:00:00 GMT+1100 (Australian Eastern Daylight Time)'` <br> - `327611110417` |
| `notes`   | string           | Notes related to the vulnerability.                       |

### GitHub Actions

```yml
steps:
  - uses: actions/checkout@v2
  - name: Audit for vulnerabilities
    run: npx audit-ci@^7 --config ./audit-ci.jsonc
```

_(Recommended)_ Run `audit-ci` immediately after checking out the git repository to reduce the risk of executing a `postinstall` script from a compromised NPM package.

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
  # This should run immediately after cloning
  # the risk of executing a script from a compromised NPM package.
  # If you use a pull-request-only workflow,
  # it's better to not run audit-ci on `main` and only run it on pull requests.
  # For more info: https://github.com/IBM/audit-ci/issues/69
  # For a PR-only workflow, use the below command instead of the above command:
  #
  # command: if [[ ! -z $CIRCLE_PULL_REQUEST ]] ; then npx audit-ci --config ./audit-ci.jsonc ; fi
  - run:
      name: run-audit-ci
      command: npx audit-ci@^7 --config ./audit-ci.jsonc
  - run:
      name: install-npm
      command: "npm install --no-audit"
```

### Travis-CI

Auditing only on PR builds is [recommended](#qa)

```yml
scripts:
  # This script should be the first that runs to reduce the risk of
  # executing a script from a compromised NPM package.
  - if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then npx audit-ci@^7 --config ./audit-ci.jsonc; fi
```

For `Travis-CI` not using PR builds:

```yml
scripts:
  - npx audit-ci@^7 --config ./audit-ci.jsonc
```

## Options

> _(Recommended)_ Prefer to use a JSONC or JSON5 config file for `audit-ci` over managing your config with CLI arguments.
> Using a config file supports workflows such as documenting your allowlist, centralized and easier config management,
> and code completion when using the `$schema` field.

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
|      | --registry        | The registry to resolve packages by name and version for auditing (default to unspecified)            |
|      | --report-type     | Format for the audit report results [_choices_: `important`, `summary`, `full`] (default `important`) |
|      | --retry-count     | The number of attempts audit-ci calls an unavailable registry before failing (default `5`)            |
|      | --config          | Path to the audit-ci configuration file                                                               |
|      | --skip-dev        | Skip auditing devDependencies (default `false`)                                                       |
|      | --extra-args      | Extra arguments to pass to the underlying audit command (default: `[]`)                               |

### Config file specification

A config file can manage auditing preferences for `audit-ci`. The config file's keys match the CLI arguments.

```txt
{
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  // Only use one of ["low": true, "moderate": true, "high": true, "critical": true]
  "low": <boolean>, // [Optional] defaults `false`
  "moderate": <boolean>, // [Optional] defaults `false`
  "high": <boolean>, // [Optional] defaults `false`
  "critical": <boolean>, // [Optional] defaults `false`
  "allowlist": <(string | [NSPRecord](#nsprecord-fields))[]>, // [Optional] default `[]`
  "report-type": <string>, // [Optional] defaults `important`
  "package-manager": <string>, // [Optional] defaults `"auto"`
  "output-format": <string>, // [Optional] defaults `"text"`
  "pass-enoaudit": <boolean>, // [Optional] defaults `false`
  "show-found": <boolean>, // [Optional] defaults `true`
  "show-not-found": <boolean>, // [Optional] defaults `true`
  "registry": <string>, // [Optional] defaults `undefined`
  "retry-count": <number>, // [Optional] defaults 5
  "skip-dev": <boolean>, // [Optional] defaults `false`
  "extra-args": <string>[] // [Optional] defaults `[]`
}
```

> Refrain from using `"directory"` within the config file because `directory`
> is relative to where the command is run, rather than the directory where the config file exists.

## Examples

### Prevents build on moderate, high, or critical vulnerabilities with allowlist; ignores low

With a `JSONC` config file, execute with `npx audit-ci --config ./audit-ci.jsonc`.

```jsonc
// audit-ci.jsonc
{
  // $schema provides code completion hints to IDEs.
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  "moderate": true,
  "allowlist": [
    // Axios denial of service https://github.com/advisories/GHSA-42xw-2xvc-qx8m
    "GHSA-42xw-2xvc-qx8m",
    // The following are for the latest create-react-app
    // https://github.com/advisories/GHSA-rp65-9cf3-cjxr
    // Alternatively, allowlist "GHSA-rp65-9cf3-cjxr" to suppress this nth-check advisory across all paths
    // or "*|react-scripts>*" to suppress advisories for all transitive dependencies of "react-scripts".
    "GHSA-rp65-9cf3-cjxr|react-scripts>@svgr/webpack>@svgr/plugin-svgo>svgo>css-select>nth-check",
  ],
}
```

Or, with the CLI:

```sh
npx audit-ci -m -a "GHSA-42xw-2xvc-qx8m" "GHSA-rp65-9cf3-cjxr|react-scripts>@svgr/webpack>@svgr/plugin-svgo>svgo>css-select>nth-check"
```

### Prevents build on any vulnerability except advisory "GHSA-38f5-ghc2-fcmv" and all of lodash and base64url, don't show allowlisted

With a `JSON5` config file:

```json5
// JSON5 files support trailing commas and more succinct syntax than JSONC files.
{
  $schema: "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  low: true,
  allowlist: ["GHSA-38f5-ghc2-fcmv", "lodash", "base64url"],
  "show-found": false,
}
```

Or, with the CLI with `yarn dlx`:

```sh
yarn dlx audit-ci@^7 -l -a "GHSA-38f5-ghc2-fcmv" lodash base64url --show-found false
```

### Prevents build with critical vulnerabilities showing the full report

With a `JSONC` config file:

```jsonc
{
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  "critical": true,
  "report-type": "full",
}
```

Or, with the CLI with `pnpm dlx`:

```sh
pnpm dlx audit-ci@^7 --critical --report-type full
```

### Continues build regardless of vulnerabilities, but show the summary report

With a `JSONC` config file:

```jsonc
{
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  "report-type": "summary",
}
```

Or, with the CLI:

```sh
npx audit-ci@^7 --report-type summary
```

### Pass additional args to Yarn Berry to exclude a certain package from audit

With a `JSONC` config file, in a project on Yarn Berry v3.3.0 or later:

```jsonc
{
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  "extra-args": ["--exclude", "example"],
}
```

Or, with the CLI:

```sh
npx audit-ci@^7 --extra-args '\--exclude' example
```

### Example config file and different directory usage

#### test/npm-config-file/audit-ci.jsonc

```jsonc
{
  "$schema": "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
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
    "*|example6>*",
  ],
  "registry": "https://registry.npmjs.org",
}
```

```sh
npx audit-ci@^7 --directory test/npm-config-file --config test/npm-config-file/audit-ci.jsonc
```

#### test/pnpm-config-file/audit-ci.json5

```json5
{
  $schema: "https://github.com/IBM/audit-ci/raw/main/docs/schema.json",
  moderate: true,
  "package-manager": "pnpm",
  allowlist: [
    "GHSA-vfvf-mqq8-rwqc",
    "example2",
    "GHSA-6354-6mhv-mvv5|example3",
    "GHSA-42xw-2xvc-qx8m|example5>example4",
    "*|example6>*",
  ],
}
```

```sh
npx audit-ci@^7 --directory test/pnpm-config-file --config test/pnpm-config-file/audit-ci.json5
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

If `audit-ci` is run on the PR build and not on the push build, you can continue to push new code and create PRs parallel to the actual vulnerability fix.
However, they can't be merged until the fix is implemented.
Since `audit-ci` performs the audit on the PR build,
it will always have the most up-to-date dependencies vs. the push build, which would require a manual merge with `main` before passing the audit.

### What do I do when NPM/Yarn is breaking my build while returning ENOAUDIT?

The config option `--pass-enoaudit` allows passing if no audit is performed due to the registry returning ENOAUDIT.
It is `false` by default to reduce the risk of merging in a vulnerable package.
However, if the convenience of passing is more important for your project then you can add `--pass-enoaudit` into the CLI or add it to the config.
