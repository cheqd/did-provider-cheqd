# Veramo SDK for cheqd: did-provider-cheqd

## ℹ️ Overview

The purpose of this package is enable users to create and update DIDs on the cheqd ledger, using the Veramo SDK. It includes veramo agent methods that can be utilised both on an application level or through the [`@veramo/cli`](https://github.com/uport-project/veramo/tree/next/packages/cli) package.

This package utilises the main functionality existing within [`@veramo/core`](https://github.com/uport-project/veramo/tree/next/packages/core) and extends this to include cheqd ledger functionality, such as creating and managing DIDs. This is the first provider plug-in that utilises the did manager update method which offers a full body update of a DID (identifier) rather than individual field update transactions (essentially through this you can pass all updates in one go, leaving the validation only on the ledger side). 

Additionally, this package enables passing of a raw payload (e.g. diddoc JSON), rather than following the field-by-field update (the method more commonly used by did providers leveraging Veramo Core) 

## 🧑‍💻🛠 Developer Guide

### Architecture

did-provider cheqd consumes functionality that exists within the [`cheqd-sdk package`](https://github.com/cheqd/sdk) in a way that complies to the Veramo `AbstractIdentifierProvider`. 

It uses the [veramo key management system](https://github.com/uport-project/veramo/tree/next/packages/key-manager) (KMS) to store the state of the client, and write to the ledger for create and update operations. 

This package works alongside the core veramo packages: 

*[`@veramo/core`](https://github.com/uport-project/veramo/tree/next/packages/core)
*[`@veramo/cli`](https://github.com/uport-project/veramo/tree/next/packages/cli)
*[`@veramo/credential-w3c`](https://github.com/uport-project/veramo/tree/next/packages/credential-w3c)

Find out about other Veramo plug-ins at: [`veramo_agent/plugins/`](https://veramo.io/docs/veramo_agent/plugins/)

### Setup

Dependencies can be installed using Yarn or any other package manager.

```bash
yarn install
```

### Config

A default agent configuration is provided with the [`agent.yml`](https://github.com/cheqd/did-provider-cheqd/blob/main/agent.yml) file. 

To specify further configurations, take a look at the Veramo docs, however ensure you retain the cheqd specific suggested configurations. 

### Deploy

did-provider cheqd supports the same out of the box use cases as Veramo provides. As such, this can be utilised in a backend (server-side) envrionment or frontend (browser/web) application, or in a CLI specific applications by leverage [`@veramo/cli`](https://github.com/uport-project/veramo/tree/next/packages/cli) 

## 📄 Documentation

Veramo offers a number of application specific guides (see below):

* [CLI Tool](https://veramo.io/docs/veramo_agent/cli_tool)
* [Node](https://veramo.io/docs/node_tutorials/node_setup_identifiers)
* [React](https://veramo.io/docs/react_tutorials/react_setup_resolver)
* [React Native](https://veramo.io/docs/react_native_tutorials/react_native_setup_identifers)

With each of the guides mentioned here, in order to customise the steps for the cheqd ledger, after insalling each veramo package dependency, install `@cheqd/did-provider-cheqd` with the package manager of your choice (yarn / npm). 

See working examples using cheqd at [INSERT LINK TO TUTORIALS]
