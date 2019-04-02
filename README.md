[![Build Status](https://travis-ci.com/IBM/audit-ci.svg?branch=master)](https://travis-ci.com/IBM/audit-ci)
![CircleCI branch](https://img.shields.io/circleci/project/github/IBM/audit-ci/master.svg)
![David](https://img.shields.io/david/IBM/audit-ci.svg)

# Overview

This module is intended to be consumed by your favourite continuous integration tool to
halt execution if `npm audit` or `yarn audit` finds vulnerabilities at or above the specified threshold.

# Set up

> `npm install --save-dev audit-ci`

or if you're using `yarn`

> `yarn add -D audit-ci`

Assuming medium, high, and critical severity vulnerabilities prevent build continuation:

For `Travis-CI` (only on PR builds is [recommended](#qa)):

```yml
scripts:
  # This script should be the first that runs to reduce the risk of
  # executing a script from a compromised NPM package.
  - if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then audit-ci --moderate; fi
```

For `Travis-CI` not using PR builds:

```yml
scripts:
  # This script should be the first that runs to reduce the risk of
  # executing a script from a compromised NPM package.
  - audit-ci --moderate
```

For `CircleCI`:

```yml
# ... excludes set up for job
steps:
  - checkout
  - run:
      name: update-npm
      command: 'sudo npm install -g npm'
  - restore_cache:
      key: dependency-cache-{{ checksum "package.json" }}
  - run:
      name: install-npm
      command: 'npm install --no-audit'
  # This should run immediately after installation to reduce
  # the risk of executing a script from a compromised NPM package.
  - run:
      name: run-audit-ci
      command: 'audit-ci --moderate'
```

### Installing as a global dependency in your CI

An alternative to installing as a devDependency is to install globally within the CI environment at run-time.

```yml
before_install:
  - if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then npm i -g audit-ci && audit-ci -m; fi
```

## Options

| Args | Alias             | Description                                                                       |
| ---- | ----------------- | --------------------------------------------------------------------------------- |
| -l   | --low             | Prevents integration with low or higher vulnerabilities (default `false`)         |
| -m   | --moderate        | Prevents integration with moderate or higher vulnerabilities (default `false`)    |
| -h   | --high            | Prevents integration with high or critical vulnerabilities (default `false`)      |
| -c   | --critical        | Prevents integration only with critical vulnerabilities (default `false`)         |
| -p   | --package-manager | Choose a package manager [_choices_: `auto`, `npm`, `yarn`] (default `auto`)      |
| -r   | --report          | Shows the full audit report (default `false`)                                     |
| -s   | --summary         | Shows the summary audit report (default `true`)                                   |
| -a   | --advisories      | Vulnerable advisory ids to whitelist from preventing integration (default `none`) |
| -w   | --whitelist       | Vulnerable modules to whitelist from preventing integration (default `none`)      |
| -d   | --directory       | The directory containing the package.json to audit (default `./`)                 |
|      | --show-not-found  | Show whitelisted advisories that are not found (default `true`)                   |
|      | --registry        | The registry to resolve packages by name and version (default to unspecified)     |
|      | --config          | Path to JSON config file                                                          |

### (_Optional_) Config file specification

A config file can manage auditing preferences `audit-ci`. The config file's keys match the CLI arguments.

```
{
  // Only use one of ["low": true, "moderate": true, "high": true, "critical": true]
  "low": <boolean>, // [Optional] defaults `false`
  "moderate": <boolean>, // [Optional] defaults `false`
  "high": <boolean>, // [Optional] defaults `false`
  "critical": <boolean>, // [Optional] defaults `false`
  "report": <boolean>, // [Optional] defaults `false`
  "summary": <boolean>, // [Optional] defaults `true`
  "package-manager": <string>, // [Optional] defaults `"auto"`
  "advisories": <number[]>, // [Optional] defaults `[]`
  "whitelist": <string[]>, // [Optional] defaults `[]`
  "show-whitelisted-advisories": <boolean>, // [Optional] defaults `true`
  "registry": <string> // [Optional] defaults `undefined`
}
```

Review the examples section for an [example of config file usage](#example-config-file-and-usage).

> Refrain from using `"directory"` within the config file because `directory`
> is relative to where the command is run, rather than the directory where the config file exists.

## Examples

### Prevents build on moderate, high, or critical vulnerabilities; ignores low

```sh
audit-ci -m
```

### Prevents build on any vulnerability except advisory 690 and all of lodash and base64url

```sh
audit-ci -l -a 690 -w lodash base64url
```

### Prevents build with critical vulnerabilities using aliases without showing the report

```sh
audit-ci --critical --report false
```

### Continues build regardless of vulnerabilities, but show the report

```sh
audit-ci
```

### Example config file and different directory usage

**test/npm-config-file/audit-ci.json**

```json
{
  "low": true,
  "package-manager": "auto",
  "advisories": [100, 101],
  "whitelist": ["example1", "example2"],
  "registry": "https://registry.npmjs.org"
}
```

```sh
audit-ci --directory test/npm-config-file --config test/npm-config-file/audit-ci.json
```

## Q&A

#### Why run `audit-ci` on PR builds for `Travis-CI` and not the push builds?

If `audit-ci` is run on the PR build and not on the push build, you can continue to push new code and create PRs parallel to the actual vulnerability fix. However, they can't be merged until the fix is implemented. Since `audit-ci` performs the audit on the PR build, it will always have the most up-to-date dependencies vs. the push build, which would require a manual merge with `master` before passing the audit.
