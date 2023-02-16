/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, @typescript-eslint/no-non-null-assertion */
// any is used for extensibility
// unused vars are kept by convention
// non-null assertion is used when we know better than the compiler that the value is not null or undefined
import {
    CheqdNetwork,
    DIDDocument,
    IKeyPair,
    MethodSpecificIdAlgo,
    VerificationMethods,
    createDidPayload,
    createDidVerificationMethod,
    createKeyPairBase64,
    createKeyPairHex,
    createVerificationKeys
} from '@cheqd/sdk'
import {
    IAgentContext,
    IKeyManager,
    IAgentPlugin,
    IPluginMethodMap,
    IAgentPluginSchema,
    IIdentifier
} from '@veramo/core'
import {
    CheqdDIDProvider,
    LinkedResource,
    TImportableEd25519Key
} from '../did-manager/cheqd-did-provider.js'
import {
    fromString,
    toString
} from 'uint8arrays'
import { v4 } from 'uuid'
import fs from 'fs'
import Debug from 'debug'

const debug = Debug('veramo:did-provider-cheqd')

type IContext = IAgentContext<IKeyManager>
type TExportedDIDDocWithKeys = { didDoc: DIDDocument, keys: TImportableEd25519Key[], versionId?: string }
type TExportedDIDDocWithLinkedResourceWithKeys = TExportedDIDDocWithKeys & { linkedResource: LinkedResource }

const CreateIdentifierMethodName = 'cheqdCreateIdentifier'
const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier'
const DeactivateIdentifierMethodName = 'cheqdDeactivateIdentifier'
const CreateResourceMethodName = 'cheqdCreateLinkedResource'
const GenerateDidDocMethodName = 'cheqdGenerateDidDoc'
const GenerateDidDocWithLinkedResourceMethodName = 'cheqdGenerateDidDocWithLinkedResource'
const GenerateKeyPairMethodName = 'cheqdGenerateIdentityKeys'
const GenerateVersionIdMethodName = 'cheqdGenerateVersionId'

const DidPrefix = 'did'
const CheqdDidMethod = 'cheqd'

export interface ICheqd extends IPluginMethodMap {
    [CreateIdentifierMethodName]: (args: any, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>
    [UpdateIdentifierMethodName]: (args: any, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>,
    [DeactivateIdentifierMethodName]: (args: any, context: IContext) => Promise<boolean>,
    [CreateResourceMethodName]: (args: any, context: IContext) => Promise<boolean>,
    [GenerateDidDocMethodName]: (args: any, context: IContext) => Promise<TExportedDIDDocWithKeys>,
    [GenerateDidDocWithLinkedResourceMethodName]: (args: any, context: IContext) => Promise<TExportedDIDDocWithLinkedResourceWithKeys>,
    [GenerateKeyPairMethodName]: (args: any, context: IContext) => Promise<TImportableEd25519Key>
    [GenerateVersionIdMethodName]: (args: any, context: IContext) => Promise<string>
}

export class Cheqd implements IAgentPlugin {
    readonly methods?: ICheqd
    readonly schema?: IAgentPluginSchema = {
        "components": {
            "schemas": {},
            "methods": {
                "cheqdCreateIdentifier": {
                    "description": "Create a new identifier",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateIdentifierArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdUpdateIdentifier": {
                    "description": "Update an identifier",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdUpdateIdentifierArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdDeactivateIdentifier": {
                    "description": "Deactivate an identifier",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdDeactivateIdentifierArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdCreateLinkedResource": {
                    "description": "Create a new resource",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateLinkedResource object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateDidDoc": {
                    "description": "Generate a new DID document to use with `createIdentifier`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateDidDocArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateDidDocWithLinkedResource": {
                    "description": "Generate a new DID document to use with `createIdentifier` and / or `createResource`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateDidDocWithLinkedResourceArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateIdentityKeys": {
                    "description": "Generate a new key pair in hex to use with `createIdentifier`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateIdentityKeysArgs object as any for extensibility"
                            }
                        }
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateVersionId": {
                    "description": "Generate a random uuid",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateVersionIdArgs object as any for extensibility"
                            }
                        }
                    },
                    "returnType": {
                        "type": "object"
                    }
                }
            }
        }
    }
    private readonly supportedDidProviders: CheqdDIDProvider[]
    private didProvider: CheqdDIDProvider;
    private providerId: string;

    constructor(args: { providers: CheqdDIDProvider[] }) {
        if (typeof args.providers !== 'object') {
            throw new Error('[did-provider-cheqd]: at least one did provider is required')
        }

        this.supportedDidProviders = args.providers
        this.didProvider = args.providers[0]
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        this.methods = {
            [CreateIdentifierMethodName]: this.CreateIdentifier.bind(this),
            [UpdateIdentifierMethodName]: this.UpdateIdentifier.bind(this),
            [DeactivateIdentifierMethodName]: this.DeactivateIdentifier.bind(this),
            [CreateResourceMethodName]: this.CreateResource.bind(this),
            [GenerateDidDocMethodName]: this.GenerateDidDoc.bind(this),
            [GenerateDidDocWithLinkedResourceMethodName]: this.GenerateDidDocWithLinkedResource.bind(this),
            [GenerateKeyPairMethodName]: this.GenerateIdentityKeys.bind(this),
            [GenerateVersionIdMethodName]: this.GenerateVersionId.bind(this)
        }
    }

    private async CreateIdentifier(args: any, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.alias !== 'string') {
            throw new Error('[did-provider-cheqd]: alias is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[did-provider-cheqd]: keys array is required')
        }

        const provider = await Cheqd.loadProvider(<DIDDocument>args.document, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await context.agent.didManagerCreate({
            kms: args.kms,
            alias: args.alias,
            provider: this.providerId,
            options: {
                document: args.document,
                keys: args.keys,
                versionId: args?.versionId,
                fee: args?.fee
            }
        })
    }

    private async UpdateIdentifier(args: any, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[did-provider-cheqd]: keys array is required')
        }

        const provider = await Cheqd.loadProvider(<DIDDocument>args.document, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await context.agent.didManagerUpdate({
            did: args.document.id,
            document: args.document,
            provider: this.providerId,
            options: {
                kms: args.kms,
                keys: args.keys,
                versionId: args?.versionId,
                fee: args?.fee
            }
        })
    }

    private async DeactivateIdentifier(args: any, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[did-provider-cheqd]: keys array is required')
        }

        const provider = await Cheqd.loadProvider(<DIDDocument>args.document, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await this.didProvider.deactivateIdentifier({
            did: args.document.id,
            document: args.document,
            options: {
                keys: args.keys,
                fee: args?.fee
            }
        }, context)
    }

    private async CreateResource(args: any, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.payload !== 'object') {
            throw new Error('[did-provider-cheqd]: payload object is required')
        }

        if (typeof args.signInputs !== 'object') {
            throw new Error('[did-provider-cheqd]: signInputs array is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        if (args?.file) {
            args.payload.data = toString(await Cheqd.getFile(args.file), 'base64')
        }

        if (typeof args?.payload?.data === 'string') {
            args.payload.data = fromString(args.payload.data, 'base64')
        }

        this.providerId = Cheqd.generateProviderId(args.network)
        this.didProvider = await Cheqd.loadProvider({ id: this.providerId } as DIDDocument, this.supportedDidProviders)

        return await this.didProvider.createResource({
            options: {
                kms: args.kms,
                payload: args.payload,

                signInputs: args.signInputs,
                fee: args?.fee
            }
        }, context)
    }

    private async GenerateDidDoc(
        args: { verificationMethod: VerificationMethods, methodSpecificIdAlgo: MethodSpecificIdAlgo, network: CheqdNetwork }, 
        context: IContext
    ): Promise<TExportedDIDDocWithKeys> {
        if (typeof args.verificationMethod !== 'string') {
            throw new Error('[did-provider-cheqd]: verificationMethod is required')
        }

        if (typeof args.methodSpecificIdAlgo !== 'string') {
            throw new Error('[did-provider-cheqd]: methodSpecificIdAlgo is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        const keyPair = createKeyPairBase64()
        const keyPairHex: IKeyPair = { publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'), privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex') }
        const verificationKeys = createVerificationKeys(keyPair.publicKey, args.methodSpecificIdAlgo, 'key-1', args.network)
        const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys])

        return {
            didDoc: createDidPayload(verificationMethods, [verificationKeys]),
            versionId: v4(),
            keys: [
                {
                    publicKeyHex: keyPairHex.publicKey,
                    privateKeyHex: keyPairHex.privateKey,
                    kid: keyPairHex.publicKey,
                    type: 'Ed25519'
                }
            ]
        }
    }

    private async GenerateDidDocWithLinkedResource(args: any, context: IContext): Promise<TExportedDIDDocWithLinkedResourceWithKeys> {
        if (typeof args.verificationMethod !== 'string') {
            throw new Error('[did-provider-cheqd]: verificationMethod is required')
        }

        if (typeof args.methodSpecificIdAlgo !== 'string') {
            throw new Error('[did-provider-cheqd]: methodSpecificIdAlgo is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        const keyPair = createKeyPairBase64()
        const keyPairHex: IKeyPair = { publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'), privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex') }
        const verificationKeys = createVerificationKeys(keyPair.publicKey, args.methodSpecificIdAlgo, 'key-1', args.network)
        const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys])
        const payload = createDidPayload(verificationMethods, [verificationKeys])

        return {
            didDoc: payload,
            versionId: v4(),
            keys: [
                {
                    publicKeyHex: keyPairHex.publicKey,
                    privateKeyHex: keyPairHex.privateKey,
                    kid: keyPairHex.publicKey,
                    type: 'Ed25519'
                }
            ],
            linkedResource: {
                id: v4(),
                collectionId: payload.id.split(':').reverse()[0],
                name: 'sample json resource',
                version: '1.0.0',
                resourceType: 'SampleResource',
                alsoKnownAs: [],
                data: toString(new TextEncoder().encode(
                    JSON.stringify({ sample: 'json' })
                ), 'base64'),
            }
        }
    }

    private async GenerateIdentityKeys(args: any, context: IContext): Promise<TImportableEd25519Key> {
        const keyPair = createKeyPairHex()
        return {
            publicKeyHex: keyPair.publicKey,
            privateKeyHex: keyPair.privateKey,
            kid: keyPair.publicKey,
            type: 'Ed25519'
        }
    }

    private async GenerateVersionId(args: any, context: IContext): Promise<string> {
        return v4()
    }

    static async loadProvider(document: DIDDocument, providers: CheqdDIDProvider[]): Promise<CheqdDIDProvider> {
        const provider = providers.find((provider) => document.id.includes(`${DidPrefix}:${CheqdDidMethod}:${provider.network}`))
        if (!provider) {
            throw new Error(`[did-provider-cheqd]: Provider namespace not found`)
        }
        return provider
    }

    static generateProviderId(namespace: string): string {
        return `${DidPrefix}:${CheqdDidMethod}:${namespace}`
    }

    static async getFile(filename: string): Promise<Uint8Array> {
        if (typeof filename !== 'string') {
            throw new Error('[did-provider-cheqd]: filename is required')
        }

        if (!fs.existsSync(filename)) {
            debug(`[did-provider-cheqd]: File ${filename} not found`)
            throw new Error(`[did-provider-cheqd]: File ${filename} not found`)
        }

        return new Promise((resolve, reject) => {
            const content = fs.readFileSync(filename)
            if (!content) {
                reject(new Error(`[did-provider-cheqd]: File ${filename} is empty`))
            }
            resolve(new Uint8Array(content))
        })
    }
}
