# Veramo plugin template

This template repository provides a bare-bones structure for writing an agent plugin for Veramo and/or for providing
your own implementations for key management and storage, or for DID storage.

## Quick start

- Copy this repo
- Rename package in `package.json`
- `yarn`
- `yarn build` or `yarn watch`
- `yarn generate-plugin-schema`
- `yarn start` or VSCode Debugger (CMD + Shift + D) > Run `OpenAPI server`

## Structure of this template

### 1. Custom DID management templates

You can change [how DIDs are stored](./src/did-manager/my-did-store.ts) by Veramo. You can implement support for other
DID methods by overriding [MyIdentifierProvider](./src/did-manager/my-identifier-provider.ts)

### 2. Use your plugin with @veramo/cli

See [./agent.yml](./agent.yml) for an example Veramo CLI configuration that uses the plugin and customizations from this
template alongside other Veramo plugins to create a fully functioning agent.

## Testing your plugin

There are a number of ways to test your plugin.

### Integration tests

Will be added in the nearest future.

### Call your agent using the Veramo OpenAPI server

You can also run `yarn veramo server` in your terminal and then go to <http://localhost:3335/api-docs> to see all the
available plugin methods. You can call them after you click Authorize and provide the API key defined
in [agent.yml](./agent.yml#L119). By default, it is `test123`.

### Step by step debugging

This repository includes some [Visual Studio Code launch configurations](./.vscode/launch.json) that can be used for
step by step debugging.
