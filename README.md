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
  - audit-ci --moderate
  # If you use a pull-request-only workflow,
  # it's better to not run audit-ci on master and only run it on pull requests.
  # For more info: https://github.com/IBM/audit-ci/issues/69
  # For a PR-only workflow, use the below script instead of the above script:
  #
  # - if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then audit-ci --moderate; fi
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
      # Only have audit-ci checks on pull requests
      command: audit-ci --moderate
      # If you use a pull-request-only workflow,
      # it's better to not run audit-ci on master and only run it on pull requests.
      # For more info: https://github.com/IBM/audit-ci/issues/69
      # For a PR-only workflow, use the below command instead of the above command:
      #
      # command: if [[ ! -z $CIRCLE_PULL_REQUEST ]] ; then audit-ci --moderate ; fi
```

### NPX

An alternative to installing as a devDependency is to use npx to install within the CI environment at run-time.

```yml
before_install:
  - npx audit-ci -m
```

## Options

| Args | Alias             | Description                                                                                           |
| ---- | ----------------- | ----------------------------------------------------------------------------------------------------- |
| -l   | --low             | Prevents integration with low or higher vulnerabilities (default `false`)                             |
| -m   | --moderate        | Prevents integration with moderate or higher vulnerabilities (default `false`)                        |
| -h   | --high            | Prevents integration with high or critical vulnerabilities (default `false`)                          |
| -c   | --critical        | Prevents integration only with critical vulnerabilities (default `false`)                             |
| -p   | --package-manager | Choose a package manager [_choices_: `auto`, `npm`, `yarn`] (default `auto`)                          |
| -a   | --advisories      | Vulnerable advisory ids to whitelist from preventing integration (default `none`)                     |
| -w   | --whitelist       | Vulnerable modules to whitelist from preventing integration (default `none`)                          |
|      | --path-whitelist  | Vulnerable module paths to whitelist from preventing integration (default `none`)                     |
| -d   | --directory       | The directory containing the package.json to audit (default `./`)                                     |
|      | --pass-enoaudit   | Pass if no audit is performed due to the registry returning ENOAUDIT (default `false`)                |
|      | --show-not-found  | Show whitelisted advisories that are not found (default `true`)                                       |
|      | --registry        | The registry to resolve packages by name and version (default to unspecified)                         |
|      | --report-type     | Format for the audit report results [_choices_: `important`, `summary`, `full`] (default `important`) |
|      | --retry-count     | The number of attempts audit-ci calls an unavailable registry before failing (default `5`)            |
|      | --config          | Path to JSON config file                                                                              |
| -r   | --report          | [_DEPRECATED_] (Use `--report-type full`) Shows the full audit report (default `false`)               |
| -s   | --summary         | [_DEPRECATED_] (Use `--report-type summary`) Shows the summary audit report (default `false`)         |

### (_Optional_) Config file specification

A config file can manage auditing preferences `audit-ci`. The config file's keys match the CLI arguments.

```
{
  // Only use one of ["low": true, "moderate": true, "high": true, "critical": true]
  "low": <boolean>, // [Optional] defaults `false`
  "moderate": <boolean>, // [Optional] defaults `false`
  "high": <boolean>, // [Optional] defaults `false`
  "critical": <boolean>, // [Optional] defaults `false`
  "report-type": <string>, // [Optional] defaults `important`
  "package-manager": <string>, // [Optional] defaults `"auto"`
  "advisories": <number[]>, // [Optional] defaults `[]`
  "whitelist": <string[]>, // [Optional] defaults `[]`
  "path-whitelist": <string[]>, // [Optional] defaults `[]`
  "pass-enoaudit": <boolean>, // [Optional] defaults `false`
  "show-not-found": <boolean>, // [Optional] defaults `true`
  "registry": <string>, // [Optional] defaults `undefined`
  "retry-count": // [Optional] defaults 5
}
```

Review the examples section for an [example of config file usage](#example-config-file-and-different-directory-usage).

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

### Prevents build with critical vulnerabilities showing the full report

```sh
audit-ci --critical --report-type full
```

### Continues build regardless of vulnerabilities, but show the summary report

```sh
audit-ci --report-type summary
```

### Example config file and different directory usage

**test/npm-config-file/audit-ci.json**

```json
{
  "low": true,
  "package-manager": "auto",
  "advisories": [100, 101],
  "whitelist": ["example1", "example2"],
  "path-whitelist": ["52|example3", "880|example4", "880|example5>example4"],
  "registry": "https://registry.npmjs.org"
}
```

```sh
audit-ci --directory test/npm-config-file --config test/npm-config-file/audit-ci.json
```

## Q&A

#### Why run `audit-ci` on PR builds for `Travis-CI` and not the push builds?

If `audit-ci` is run on the PR build and not on the push build, you can continue to push new code and create PRs parallel to the actual vulnerability fix. However, they can't be merged until the fix is implemented. Since `audit-ci` performs the audit on the PR build, it will always have the most up-to-date dependencies vs. the push build, which would require a manual merge with `master` before passing the audit.

#### NPM/Yarn is returning ENOAUDIT and is breaking my build, what do I do?

The config option `--pass-enoaudit` allows passing if no audit is performed due to the registry returning ENOAUDIT. It is `false` by default to reduce the risk of merging in a vulnerable package. However, if the convenience of passing is more important for your project then you can add `--pass-enoaudit` into the CLI or add it to the config.
