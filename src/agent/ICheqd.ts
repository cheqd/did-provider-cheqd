import {
    IAgentContext,
    IKeyManager,
    IAgentPlugin,
    IPluginMethodMap,
    IAgentPluginSchema,
    IIdentifier
} from '@veramo/core'
import { CheqdDIDProvider } from '../did-manager/cheqd-did-provider'

type IContext = IAgentContext<IKeyManager>

const CreateIdentifierMethodName = 'cheqdCreateIdentifier'
const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier'

export interface ICheqd extends IPluginMethodMap {
    [CreateIdentifierMethodName]: (args: any, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>
    [UpdateIdentifierMethodName]: (args: any, context: IContext) => Promise<void>
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
                "cheqdUpdateIdentifier": {}
            }
        }
    }

    readonly didProvider: CheqdDIDProvider;

    constructor(provider: CheqdDIDProvider) {
        this.didProvider = provider

        this.methods = {
            [CreateIdentifierMethodName]: this.CreateIdentifier.bind(this),
            [UpdateIdentifierMethodName]: this.UpdateIdentifier.bind(this)
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

        if (Array.isArray(args?.keys)) {
            throw new Error('[cheqd-plugin]: keys array is required')
        }

        return await this.didProvider.createIdentifier({
            kms: args.kms,
            alias: args.alias,
            options: {
                document: args.document,
                keys: args.keys
            }
        }, context)
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

        return await this.didProvider.updateIdentifier({
            did: args.did,
            document: args.document,
        }, context)
    }
}
