# Veramo SDK plugin for cheqd DID method

[![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/cheqd/did-provider-cheqd/Workflow%20Dispatch/main?label=Lint%2C%20Build%2C%20Test&style=flat-square)](https://github.com/cheqd/did-provider-cheqd/actions/workflows/dispatch.yml) [![npm (scoped)](https://img.shields.io/npm/v/@cheqd/did-provider-cheqd?style=flat-square)](https://www.npmjs.com/package/@cheqd/did-provider-cheqd)

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cheqd/did-provider-cheqd?color=green&label=stable&sort=semver&style=flat-square)](https://github.com/cheqd/did-provider-cheqd/releases/latest) ![GitHub Release Date](https://img.shields.io/github/release-date/cheqd/did-provider-cheqd?style=flat-square)

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/cheqd/did-provider-cheqd?include_prereleases&label=latest%20%28incl.%20pre-release%29&sort=semver&style=flat-square)](https://github.com/cheqd/did-provider-cheqd/releases/) ![GitHub commits since latest release (by date)](https://img.shields.io/github/commits-since/cheqd/did-provider-cheqd/latest?style=flat-square)

[![GitHub contributors](https://img.shields.io/github/contributors/cheqd/did-provider-cheqd?style=flat-square)](https://github.com/cheqd/did-provider-cheqd/graphs/contributors) ![GitHub repo size](https://img.shields.io/github/repo-size/cheqd/did-provider-cheqd?style=flat-square)

## ℹ️ Overview

The purpose of this [`@cheqd/did-provider-cheqd` NPM package](https://www.npmjs.com/package/@cheqd/did-provider-cheqd) is to enable developers to interact with the cheqd ledger using [Veramo SDK](https://veramo.io/), a modular and pluggable client app SDK for decentralised identity and SSI applications.

This package includes [Veramo SDK Agent methods](https://veramo.io/docs/veramo_agent/plugins) for use with the [Veramo CLI NPM package](https://www.npmjs.com/package/@veramo/cli). It can also be consumed as an NPM package outside Veramo CLI for building your own applications with NPM.

The package's core functionality is borrowed from [Veramo Core NPM package](https://www.npmjs.com/package/@veramo/core). and extends this to include cheqd ledger functionality, such as creating and managing DIDs.

### 🆔 `did:cheqd`-specific functionality

`did-provider-cheqd` is the first Veramo SDK plug-in that utilises the *DID Manager Update* method to offer a full-body DIDDoc update for a DID on cheqd ledger, rather than individual field update transactions used more commonly in other DID methods such as [`did:ethr`](https://developer.uport.me/ethr-did/docs/index).

New DID creation can also be done by passing a full-body DIDoc payload in JSON, rather than having to assemble the document field-by-field.

## 📚 Tutorials

Extensive [tutorials on how to use Veramo SDK for cheqd](https://docs.cheqd.io/identity/veramo-sdk-for-cheqd) are available on the [cheqd Identity Documentationn site](https://docs.cheqd.io/identity/).

## 🧑‍💻🛠 Developer Guide

### Setup

Dependencies can be installed [using NPM](https://docs.npmjs.com/cli/v8/commands) or similar package package managers using the `package.json` in this repository.

```bash
npm install
```

### Configuration

A default Veramo Agent configuration is provided in the [`agent.yml`](https://github.com/cheqd/did-provider-cheqd/blob/main/agent.yml) file in this repository.

⚠️ Here are the values that you are recommended to edit before usage:

1. `dbEncryptionKey`: Encryption key for Veramo KMS local storage [SQLite database](https://www.sqlite.org/index.html). If you don't change this, the default database encryption key present in the file is used.
2. `cosmosPayerMnemonic`: Mnemonic for the cheqd Cosmos account from which the fees for any transactions are paid.

## 💬 Community

The [**cheqd Community Slack**](http://cheqd.link/join-cheqd-slack) is our primary chat channel for the open-source community, software developers, and node operators.

Please reach out to us there for discussions, help, and feedback on the project.

## 🙋 Find us elsewhere

[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge\&logo=telegram\&logoColor=white)](https://t.me/cheqd) [![Discord](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge\&logo=discord\&logoColor=white)](http://cheqd.link/discord-github) [![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge\&logo=twitter\&logoColor=white)](https://twitter.com/intent/follow?screen\_name=cheqd\_io) [![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge\&logo=linkedin\&logoColor=white)](http://cheqd.link/linkedin) [![Slack](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge\&logo=slack\&logoColor=white)](http://cheqd.link/join-cheqd-slack) [![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge\&logo=medium\&logoColor=white)](https://blog.cheqd.io) [![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge\&logo=youtube\&logoColor=white)](https://www.youtube.com/channel/UCBUGvvH6t3BAYo5u41hJPzw/)
