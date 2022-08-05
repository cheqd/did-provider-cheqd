# Veramo SDK for cheqd: did-provider-cheqd

## ℹ️ Overview

The purpose of this package is enable users to create and update DIDs on the cheqd ledger, using the Veramo SDK. It includes veramo agent methods that can be utilised both on an application level or through the [`@veramo/cli`](https://github.com/uport-project/veramo/tree/next/packages/cli) package.

The packages utilises the main functionality existing within [`@veramo/core`](https://github.com/uport-project/veramo/tree/next/packages/core) and extends this to include cheqd ledger functionality, such as creating and managing DIDs.

This is the first provider plug-in that utilises the `did manager update` method which offers a full body update of a DID (identifier) rather than individual field update transactions used more commonly. Through this through it is possible pass all did updates in one transaction.

Additionally, this package enables passing of a raw payload (e.g. a diddoc JSON), rather than following the field-by-field update, also more commonly used by did providers leveraging Veramo Core)

## 🧑‍💻🛠 Developer Guide

### Architecture

did-provider cheqd consumes functionality that exists within the [`cheqd-sdk package`](https://github.com/cheqd/sdk) in a way that complies to the Veramo `AbstractIdentifierProvider`. You do not need to install the `cheqd-sdk package`](https://github.com/cheqd/sdk) as this is included within `package.json`.

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