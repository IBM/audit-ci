[![Build Status](https://travis-ci.com/IBM/audit-ci.svg?branch=master)](https://travis-ci.com/IBM/audit-ci)
![CircleCI branch](https://img.shields.io/circleci/project/github/IBM/audit-ci/master.svg)
![David](https://img.shields.io/david/IBM/audit-ci.svg)

# Overview

This module is intended to be consumed by your favourite continuous integration tool to
halt execution if `npm audit` finds vulnerabilities at or above the specified threshold.

# Set up

Assuming medium, high, and critical severity vulnerabilities prevent build continuation:

For `Travis-CI` using PR builds (*recommended*):

```yml
before_install:
  - if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then npm i -g audit-ci@latest && audit-ci -m; fi
```

For `Travis-CI` not using PR builds (*not recommended*):

```yml
before_install:
  - npm i -g audit-ci@latest && audit-ci -m
```


For `CircleCI`:

```yml
# ... excludes set up for job 
 steps:
  - checkout
  - run:
      name: update-npm 
      command: 'sudo npm i -g npm@latest'
  - restore_cache:
      key: dependency-cache-{{ checksum "package.json" }}
  - run:
      name: install-and-run-audit-ci
      command: 'sudo npm i -g audit-ci@latest && audit-ci -m'
  - run:
      name: install-npm
      command: npm i
```

## Options

| Args | Alias       | Description                                                                    |
|------|-------------|--------------------------------------------------------------------------------|
| -l   | --low       | Prevents integration with low or higher vulnerabilities (default `false`)      |
| -m   | --moderate  | Prevents integration with moderate or higher vulnerabilities (default `false`) |
| -h   | --high      | Prevents integration with high or critical vulnerabilities (default `false`)   |
| -c   | --critical  | Prevents integration only with critical vulnerabilities (default `false`)      |
| -r   | --report    | Shows the `npm audit --json` report (default `true`)                           |
| -w   | --whitelist | Vulnerable modules to whitelist from preventing integration (default `none`)   |

## Examples

### Prevents build on moderate, high, or critical vulnerabilities; ignores low
```sh
npm i -g audit-ci@latest && audit-ci -m
```

### Prevents build on any vulnerability except lodash (low) and base64url (moderate)
```sh
npm i -g audit-ci@latest && audit-ci -l -w lodash base64url
```

### Prevents build with critical vulnerabilities using aliases without showing the report
```sh
npm i -g audit-ci@latest && audit-ci --critical --report false
```

### Continues build regardless of vulnerabilities, but show the report
```sh
npm i -g audit-ci@latest && audit-ci
```

## Q&A

> Why run `audit-ci` on PR builds for `Travis` and not the push builds?

If `audit-ci` is run on the PR build and not on the push build, you can continue to push new code and create PRs parallel to the actual vulnerability fix. However, they can't be merged until the fix is implemented. Since `audit-ci` performs the audit on the PR build, it will always have the most up-to-date dependencies vs. the push build, which would require a manual merge with `master` before passing the audit.