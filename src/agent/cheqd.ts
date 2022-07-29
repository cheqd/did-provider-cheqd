import {
    IAgentContext,
    IKeyManager,
    IAgentPlugin,
    IPluginMethodMap,
    IAgentPluginSchema
} from '@veramo/core'
import { CheqdDIDProvider } from '../did-manager/cheqd-did-provider'

type IContext = IAgentContext<IKeyManager>

export class Cheqd implements IAgentPlugin {
    readonly methods?: IPluginMethodMap
    readonly schema?: IAgentPluginSchema;

    constructor(didProviderCheqd: CheqdDIDProvider) {
        this.methods = {
            'cheqdCreateIdentifierRaw': async (args: any, context: IContext): Promise<any> => {
                if (!args.payload) {
                    throw new Error('payload is required')
                }

                return await didProviderCheqd.createIdentifierRaw(args.payload)
            },
        }

        // z-schema rules
        // https://github.com/zaggino/z-schema
        this.schema = {
            components: {
                schemas: {},
                methods: {
                    'cheqdCreateIdentifierRaw': {
                        arguments: {},
                        // This property is required
                        returnType: {}
                    }
                }
            }
        }
    }
}
