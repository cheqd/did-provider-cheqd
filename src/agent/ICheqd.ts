import { CheqdNetwork, IKeyPair, MethodSpecificIdAlgo, VerificationMethods } from '@cheqd/sdk/build/types'
import { createDidPayload, createDidVerificationMethod, createKeyPairBase64, createKeyPairHex, createVerificationKeys } from '@cheqd/sdk'
import {
    IAgentContext,
    IKeyManager,
    IAgentPlugin,
    IPluginMethodMap,
    IAgentPluginSchema,
    IIdentifier
} from '@veramo/core'
import { IdentifierPayload, TImportableEd25519Key } from '../did-manager/cheqd-did-provider'
import { fromString, toString } from 'uint8arrays'

type IContext = IAgentContext<IKeyManager>
type TExportedDIDDocWithKeys = { didDoc: IdentifierPayload, keys: TImportableEd25519Key }

const CreateIdentifierMethodName = 'cheqdCreateIdentifier'
const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier'
const GenerateDidDocMethodName = 'cheqdGenerateDidDoc'
const GenerateKeyPairMethodName = 'cheqdGenerateIdentityKeys'

export interface ICheqd extends IPluginMethodMap {
    [CreateIdentifierMethodName]: (args: any, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>
    [UpdateIdentifierMethodName]: (args: any, context: IContext) => Promise<void>,
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
                "cheqdGenerateDidDoc": {
                    "description": "Generate a new DID document to use with `createIdentifier`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateDidDocArgs object as any for extensibility"
                            }
                        }
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
                    }
                }
            }
        }
    }
    readonly didProvider: string;

    constructor(args: { provider: string }) {
        if (typeof args.provider !== 'string') {
            throw new Error('[cheqd-plugin]: provider is required')
        }

        this.didProvider = args.provider

        this.methods = {
            [CreateIdentifierMethodName]: this.CreateIdentifier.bind(this),
            [UpdateIdentifierMethodName]: this.UpdateIdentifier.bind(this),
            [GenerateDidDocMethodName]: this.GenerateDidDoc.bind(this),
            [GenerateKeyPairMethodName]: this.GenerateIdentityKeys.bind(this)
        }
    }

    private async CreateIdentifier(args: any, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
        if (typeof args.kms !== 'string') {
            throw new Error('[cheqd-plugin]: kms is required')
        }

        if (typeof args.alias !== 'string') {
            throw new Error('[cheqd-plugin]: alias is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[cheqd-plugin]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[cheqd-plugin]: keys array is required')
        }

        return await context.agent.didManagerCreate({
            kms: args.kms,
            alias: args.alias,
            provider: this.didProvider,
            options: {
                document: args.document,
                keys: args.keys
            }
        })
    }

    private async UpdateIdentifier(args: any, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[cheqd-plugin]: kms is required')
        }

        if (typeof args.did !== 'string') {
            throw new Error('[cheqd-plugin]: did is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[cheqd-plugin]: document object is required')
        }

        if (typeof args.keys !== 'object') {
            throw new Error('[cheqd-plugin]: keys array is required')
        }

        return await context.agent.didManagerUpdate({
            did: args.did,
            document: args.document,
            provider: this.didProvider,
            options: {
                kms: args.kms,
                keys: args.keys
            }
        })
    }

    private async GenerateDidDoc(
        args: { verificationMethod: VerificationMethods, methodSpecificIdAlgo: MethodSpecificIdAlgo, methodSpecificIdLength: 16 | 32, network: CheqdNetwork }, 
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        context: IContext
    ): Promise<TExportedDIDDocWithKeys> {
        if (typeof args.verificationMethod !== 'string') {
            throw new Error('[cheqd-plugin]: verificationMethod is required')
        }

        if (typeof args.methodSpecificIdAlgo !== 'string') {
            throw new Error('[cheqd-plugin]: methodSpecificIdAlgo is required')
        }

        if (typeof args.methodSpecificIdLength !== 'number') {
            throw new Error('[cheqd-plugin]: methodSpecificIdLength is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[cheqd-plugin]: network is required')
        }

        const keyPair = createKeyPairBase64()
        const keyPairHex: IKeyPair = { publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'), privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex') }
        const verificationKeys = createVerificationKeys(keyPair, args.methodSpecificIdAlgo, 'key-1', args.methodSpecificIdLength, args.network)
        const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys])

        return {
            didDoc: createDidPayload(verificationMethods, [verificationKeys]),
            keys: {
                publicKeyHex: keyPairHex.publicKey,
                privateKeyHex: keyPairHex.privateKey,
                kid: keyPairHex.publicKey,
                type: 'Ed25519'
            }
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    private async GenerateIdentityKeys(args: any, context: IContext): Promise<TImportableEd25519Key> {
        const keyPair = createKeyPairHex()
        return {
            publicKeyHex: keyPair.publicKey,
            privateKeyHex: keyPair.privateKey,
            kid: keyPair.publicKey,
            type: 'Ed25519'
        }
    }
}
