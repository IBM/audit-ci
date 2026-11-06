## Contributing In General

Our project welcomes external contributions. If you have an itch, please feel
free to scratch it.

To contribute code or documentation, please submit a [pull request](https://github.com/ibm/audit-ci/pulls).

### Proposing new features

If you would like to implement a new feature, please [raise an issue](https://github.com/ibm/audit-ci/issues)
before sending a pull request so the feature can be discussed. This is to avoid
you wasting your valuable time working on a feature that the project developers
are not interested in accepting into the code base.

### Fixing bugs

If you would like to fix a bug, please [raise an issue](https://github.ibm.com/IBM/audit-ci/issues) before sending a
pull request so it can be tracked.

### Merge approval

The project maintainers use the GitHub reviewer functionality to indicate acceptance or to request changes.

For a list of the maintainers, see the [MAINTAINERS.md](MAINTAINERS.md) page.

## Setup

Use Node 22.12.0 or newer. CI tests that minimum version and the current Node 24 and 26 releases.

1. `git clone git@github.com:IBM/audit-ci.git`
1. `cd audit-ci`
1. `npm install`

## Testing

Tests use Vitest in the `test` directory. Run `npm test -- --run` for the full suite, `npm run coverage` to check the 90% coverage thresholds, and `npm run check:ci` for lint and formatting checks. Yarn reporting tests use recorded audit output so registry changes do not affect their results; subprocess tests cover command arguments and error handling separately.

`npm run build` cleans `dist` and emits ESM JavaScript and TypeScript declarations using TypeScript directly. `npm run test:package` builds and packs the package, installs it into a temporary consumer project, and checks the CLI, ESM imports, CommonJS dynamic imports, and declarations. The package check requires registry access to install production dependencies. `npm pack` also rebuilds automatically through `prepack`.

The v8 prerelease uses the `next` npm tag through `publishConfig.tag`. When preparing the stable `8.0.0` release, change that tag to `latest` together with the version.
