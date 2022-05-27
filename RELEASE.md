
# Overview

## Tags

Here we are going to use tags from eslint plugin:

### The Tag is one of the following

- Fix - for a bug fix.
- Update - either for a backwards-compatible enhancement or for a rule change that adds reported problems.
- New - implemented a new feature.
- Breaking - for a backwards-incompatible enhancement or feature.
- Docs - changes to documentation only.
- Build - changes to build process only.
- Upgrade - for a dependency upgrade.
- Chore - for refactoring, adding tests, etc. (anything that isn't user-facing).

## Version changing

`Breaking` tag will trigger the changing of `minor` number in version
`New`, `Update` will change the `patch`
Others will not change version number.
For example, the next commit message will trigger a `minor` number changing:

```text
Breaking: Change the logic of transaction handling
```

And the next message will change only a `patch` number:

```text
New: Add new transaction type
```

## How to setup

### `semantic-release` related packages

It's neede to setup the next packages as `devDependencies` in `package.json`:

```text
    "@semantic-release/commit-analyzer": "^9.0.2",
    "@semantic-release/release-notes-generator": "^10.0.3",
    "@semantic-release/npm": "^9.0.1",
    "@semantic-release/github": "^8.0.4",
    "@semantic-release/changelog": "^6.0.1",
    "conventional-changelog-eslint": "^3.0.9",
    "semantic-release": "^19.0.2",
```

- `conventional-changelog-eslint` is needed for analyzing commits in `eslint` style as described  [here](https://github.com/conventional-changelog/conventional-changelog/tree/master/packages/conventional-changelog-eslint)

### Semantic config

For now, the main config is placed in the root directory, and file named as `.releaserc`:

```yaml
{
    "branches": [
        {
            name: 'release/1.0.x',
        },
        {
            name: 'release/1.1.x',
        }
    ],
    "debug": "true",
    "plugins": [
        [
            "@semantic-release/commit-analyzer",
            {
                "preset": "eslint",
                "releaseRules": [
                   {
                     "tag": "Breaking",
                     "release": "minor"
                   },
                   {"tag": "New", "release": "patch"},
                   {"tag": "Update", "release": "patch"},
                ],
            }
        ],
        [
            "@semantic-release/changelog",
            {
                "changelogFile": "CHANGELOG.md"
            }
        ],
        [
            "@semantic-release/release-notes-generator",
            {
                "preset": "eslint"
            }
        ],
        "@semantic-release/npm",
        [
            "@semantic-release/github",
            {
              "assets": ["dist/**", "CHANGELOG.md"]
            }
        ],
    ]
}
```

`branches` parameter is describing what the branches will be used for creating releases in the future. For the format as `release/1.0.x` is suggested.

P.S.
For now, functionality of `range` parameter for `branches` is broken and we cannot use the ability to fail wth error in case of trying to make a breaking change release inside the current family.

### Workflow steps

Due to github actions steps the main thing here is the command `npx semantic-release --debug` that will run the whole process for analyzing, checking and publishing release with artifacts. Also, pacakge will be published to npm registry
The example of this workflow can be:

```yaml
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      # Setup .npmrc file to publish to GitHub Packages
      - uses: actions/setup-node@v3
        with:
          node-version: '14.x'
      - run: npm install
      - run: npx semantic-release --debug
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### NPM registry

For now, we are using github as a npm registry. The file with registry address de to this:
`.npmrc`:

```file
@cheqd:registry=https://npm.pkg.github.com
```
