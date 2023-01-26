/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, @typescript-eslint/no-non-null-assertion */
// any is used for extensibility
// unused vars are kept by convention
// non-null assertion is used when we know better than the compiler that the value is not null or undefined
import { 
    CheqdNetwork,
    DIDDocument,
    IKeyPair,
    MethodSpecificIdAlgo,
    VerificationMethods 
} from '@cheqd/sdk/build/types'
import {
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
import { CheqdDIDProvider, TImportableEd25519Key } from '../did-manager/cheqd-did-provider';
import { fromString, toString } from 'uint8arrays'

type IContext = IAgentContext<IKeyManager>
type TExportedDIDDocWithKeys = { didDoc: DIDDocument, keys: TImportableEd25519Key[] }

const CreateIdentifierMethodName = 'cheqdCreateIdentifier'
const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier'
const DeactivateIdentifierMethodName = 'cheqdDeactivateIdentifier'
const CreateResourceMethodName = 'cheqdCreateResource'
const GenerateDidDocMethodName = 'cheqdGenerateDidDoc'
const GenerateKeyPairMethodName = 'cheqdGenerateIdentityKeys'

const DidPrefix = 'did'
const CheqdDidMethod = 'cheqd'

export interface ICheqd extends IPluginMethodMap {
    [CreateIdentifierMethodName]: (args: any, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>
    [UpdateIdentifierMethodName]: (args: any, context: IContext) => Promise<void>,
    [DeactivateIdentifierMethodName]: (args: any, context: IContext) => Promise<boolean>,
    [CreateResourceMethodName]: (args: any, context: IContext) => Promise<void>,
    [GenerateDidDocMethodName]: (args: any, context: IContext) => Promise<TExportedDIDDocWithKeys>,
    [GenerateKeyPairMethodName]: (args: any, context: IContext) => Promise<TImportableEd25519Key>
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
                "cheqdCreateResource": {
                    "description": "Create a new resource",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateResource object as any for extensibility"
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
            [GenerateKeyPairMethodName]: this.GenerateIdentityKeys.bind(this)
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

        const provider = await Cheqd.loadProvider(document as unknown as DIDDocument, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await context.agent.didManagerCreate({
            kms: args.kms,
            alias: args.alias,
            provider: this.providerId,
            options: {
                document: args.document,
                keys: args.keys,
                fee: args?.fee
            }
        })
    }

    private async UpdateIdentifier(args: any, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.did !== 'string') {
            throw new Error('[did-provider-cheqd]: did is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[did-provider-cheqd]: keys array is required')
        }

        const provider = await Cheqd.loadProvider(document as unknown as DIDDocument, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await context.agent.didManagerUpdate({
            did: args.did,
            document: args.document,
            provider: this.providerId,
            options: {
                kms: args.kms,
                keys: args.keys,
                fee: args?.fee
            }
        })
    }

    private async DeactivateIdentifier(args: any, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.did !== 'string') {
            throw new Error('[did-provider-cheqd]: did is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[did-provider-cheqd]: keys array is required')
        }

        const provider = await Cheqd.loadProvider(document as unknown as DIDDocument, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await this.didProvider.deactivateIdentifier({
            did: args.did,
            document: args.document,
            options: {
                kms: args.kms,
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

        if (typeof args.payload !== 'object') {
            throw new Error('[did-provider-cheqd]: payload object is required')
        }

        return await this.didProvider.createResource({
            options: {
                kms: args.kms,
                payload: args.payload,
                signInputs: args.signInputs
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

    // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any
    private async GenerateIdentityKeys(args: any, context: IContext): Promise<TImportableEd25519Key> {
        const keyPair = createKeyPairHex()
        return {
            publicKeyHex: keyPair.publicKey,
            privateKeyHex: keyPair.privateKey,
            kid: keyPair.publicKey,
            type: 'Ed25519'
        }
    }

    static async loadProvider(document: DIDDocument, providers: CheqdDIDProvider[]): Promise<CheqdDIDProvider> {
        const provider = providers.find((provider) => document.id.includes(`${DidPrefix}:${CheqdDidMethod}:${provider.network}:`))
        if (!provider) {
            throw new Error(`[did-provider-cheqd]: Provider namespace not found`)
        }
        return provider
    }

    static generateProviderId(namespace: string): string {
        return `${DidPrefix}:${CheqdDidMethod}:${namespace}`
    }
}
