[![Build Status](https://travis-ci.com/IBM/audit-ci.svg?branch=master)](https://travis-ci.com/IBM/audit-ci)
![CircleCI branch](https://img.shields.io/circleci/project/github/IBM/audit-ci/master.svg)
![David](https://img.shields.io/david/IBM/audit-ci.svg)

# Overview

This module is intended to be consumed by your favourite continuous integration tool to
halt execution if `npm audit` finds vulnerabilities at or above the specified threshold.

# Set up

Assuming medium, high, and critical severity vulnerabilities prevent build continuation:

For `Travis`:

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
```yml
before_install:
  - npm i -g audit-ci@latest && audit-ci -m
```

### Prevents build on any vulnerability except lodash (low) and base64url (moderate)
```yml
before_install:
  - npm i -g audit-ci@latest && audit-ci -l -w lodash base64url
```

### Prevents build with critical vulnerabilities using aliases without showing the report
```yml
before_install:
  - npm i -g audit-ci@latest && audit-ci --critical --report false
```

### Continues build regardless of vulnerabilities, but show the report
```yml
before_install:
  - npm i -g audit-ci@latest && audit-ci
```
