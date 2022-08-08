# Veramo SDK plugin for cheqd DID method

[![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/cheqd/did-provider-cheqd/Workflow%20Dispatch/main?label=Lint%2C%20Build%2C%20Test&style=flat-square)](https://github.com/cheqd/did-provider-cheqd/actions/workflows/dispatch.yml) [![npm (scoped)](https://img.shields.io/npm/v/@cheqd/did-provider-cheqd?style=flat-square)](https://www.npmjs.com/package/@cheqd/did-provider-cheqd)

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cheqd/did-provider-cheqd?color=green&label=stable&sort=semver&style=flat-square)](https://github.com/cheqd/did-provider-cheqd/releases/latest) ![GitHub Release Date](https://img.shields.io/github/release-date/cheqd/did-provider-cheqd?style=flat-square)

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/cheqd/did-provider-cheqd?include_prereleases&label=latest%20%28incl.%20pre-release%29&sort=semver&style=flat-square)](https://github.com/cheqd/did-provider-cheqd/releases/) ![GitHub commits since latest release (by date)](https://img.shields.io/github/commits-since/cheqd/did-provider-cheqd/latest?style=flat-square)

[![GitHub contributors](https://img.shields.io/github/contributors/cheqd/did-provider-cheqd?style=flat-square)](https://github.com/cheqd/did-provider-cheqd/graphs/contributors) ![GitHub repo size](https://img.shields.io/github/repo-size/cheqd/did-provider-cheqd?style=flat-square)


## ℹ️ Overview

The purpose of this [`@cheqd/did-provider-cheqd` NPM package](https://www.npmjs.com/package/@cheqd/did-provider-cheqd) is to enable developers to interact with the cheqd ledger using [Veramo SDK](https://veramo.io/), a modular and pluggable client app SDK for decentralised identity and SSI applications.

This package includes [Veramo SDK Agent methods](https://veramo.io/docs/veramo_agent/plugins) for use with the [Veramo CLI NPM package](https://www.npmjs.com/package/@veramo/cli). It can also be consumed as an NPM package outside Veramo CLI for building your own applications with NPM.

The package's core functionality is borrowed from [Veramo Core NPM package](https://www.npmjs.com/package/@veramo/core). and extends this to include cheqd ledger functionality, such as creating and managing DIDs.

## 🆔 `did:cheqd`-specific functionality

`did-provider-cheqd` is the first Veramo SDK plug-in that utilises the *DID Manager Update* method to offer a full-body DIDDoc update for a DID on cheqd ledger, rather than individual field update transactions used more commonly in other DID methods such as [`did:ethr`](https://developer.uport.me/ethr-did/docs/index).

New DID creation can also be done by passing a full-body DIDoc payload in JSON, rather than having to assemble the document field-by-field.

## 🧑‍💻🛠 Developer Guide

### Architecture

`did-provider-cheqd` consumes functionality that exists within the [`cheqd-sdk` NPM package](https://github.com/cheqd/sdk) in a way that complies to the Veramo `AbstractIdentifierProvider`. You do not need to install the `cheqd-sdk package`](https://github.com/cheqd/sdk) as this is included within `package.json`.

It uses the [veramo key management system](https://github.com/uport-project/veramo/tree/next/packages/key-manager) (KMS) to store the state of the client, and write to the ledger for create and update operations.

This package works alongside the core veramo packages:

* [`@veramo/core`](https://github.com/uport-project/veramo/tree/next/packages/core)
* [`@veramo/cli`](https://github.com/uport-project/veramo/tree/next/packages/cli)
* [`@veramo/credential-w3c`](https://github.com/uport-project/veramo/tree/next/packages/credential-w3c)

Find out about other Veramo plug-ins at [`veramo_agent/plugins/`](https://veramo.io/docs/veramo_agent/plugins/)

Below is an architecture diagram illistrating the relationships between these packages.

### Setup

Depending on the type of application you are looking to develop, you will need to install a different set of packages.

If you're looking to run a PoC type demo, or a CLI application, use the offical Veramo CLI setup guide below:

* [CLI Tool](https://veramo.io/docs/veramo_agent/cli_tool)

For other applications, see:

* [Node](https://veramo.io/docs/node_tutorials/node_setup_identifiers)
* [React](https://veramo.io/docs/react_tutorials/react_setup_resolver)
* [React Native](https://veramo.io/docs/react_native_tutorials/react_native_setup_identifers)

With each of the guides mentioned, you can customise the steps for the cheqd ledger by installing the followng, with the package manager of your choice (i.e. yarn / npm).

* `@cheqd/did-provider-cheqd`

Dependencies can be installed using Yarn or any other package manager.

```bash
yarn install
```

> You must install this package for cheqd ledger functionality to be available in the environment of choice.

### Config

A default agent configuration is provided in the [`agent.yml`](https://github.com/cheqd/did-provider-cheqd/blob/main/agent.yml) file within the `@cheqd/did-provider-cheqd` installation.

You will need to specify `cosmosPayerMnemonic`. This enables you to set the fee payer for the transactions on the cheqd network. This is NOT the DID keys.

### Deploy

`did-provider-cheqd` supports the same out of the box use cases as Veramo provides.

As such, this can be utilised in a backend (server-side) envrionment or frontend (browser/web) application, or in a CLI specific applications by leverage [`@veramo/cli`](https://github.com/uport-project/veramo/tree/next/packages/cli).

### Examples usage

> The following offers examples of how to use `did-provider-cheqd` for identity transactions.

#### Example 1: Creating a DID

```bash

```

#### Example 2: Update a DID

```bash

```

You'll find further tutorials for Verifiable Credentials and Presentations within the [cheqd identity docs site](https://docs.cheqd.io/identity/tutorials/verifiable-credentials).

## 💬 Community

The [**cheqd Community Slack**](http://cheqd.link/join-cheqd-slack) is our primary chat channel for the open-source community, software developers, and node operators.

Please reach out to us there for discussions, help, and feedback on the project.

## 🙋 Find us elsewhere

[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge\&logo=telegram\&logoColor=white)](https://t.me/cheqd) [![Discord](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge\&logo=discord\&logoColor=white)](http://cheqd.link/discord-github) [![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge\&logo=twitter\&logoColor=white)](https://twitter.com/intent/follow?screen\_name=cheqd\_io) [![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge\&logo=linkedin\&logoColor=white)](http://cheqd.link/linkedin) [![Slack](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge\&logo=slack\&logoColor=white)](http://cheqd.link/join-cheqd-slack) [![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge\&logo=medium\&logoColor=white)](https://blog.cheqd.io) [![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge\&logo=youtube\&logoColor=white)](https://www.youtube.com/channel/UCBUGvvH6t3BAYo5u41hJPzw/)
