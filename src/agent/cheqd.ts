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

export class Cheqd implements IAgentPlugin {
    readonly methods?: IPluginMethodMap
    readonly schema?: IAgentPluginSchema;

    readonly didProvider: CheqdDIDProvider;

    constructor(provider: CheqdDIDProvider) {
        this.didProvider = provider

        this.methods = {
            [CreateIdentifierMethodName]: this.CreateIdentifier.bind(this),
            [UpdateIdentifierMethodName]: this.UpdateIdentifier.bind(this)
        }

        // z-schema rules
        // https://github.com/zaggino/z-schema
        this.schema = {
            components: {
                schemas: {},
                methods: {
                    [CreateIdentifierMethodName]: {
                        arguments: {},
                        // This property is required
                        returnType: {}
                    },
                    [UpdateIdentifierMethodName]: {
                        arguments: {},
                        returnType: {}
                    }
                }
            }
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

        return await this.didProvider.createIdentifier({
            kms: args.kms,
            alias: args.alias,
            options: {
                document: args.document
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
