import { IAgentPlugin } from '@veramo/core'
import { IMyAgentPlugin, IMyAgentPluginFooArgs, IRequiredContext, IMyAgentPluginFooResult } from '../types/IMyAgentPlugin'
import { schema } from '../index'

/**
 * {@inheritDoc IMyAgentPlugin}
 * @beta
 */
export class MyAgentPlugin implements IAgentPlugin {
  readonly schema = schema.IMyAgentPlugin

  // map the methods your plugin is declaring to their implementation
  readonly methods: IMyAgentPlugin = {
    myPluginFoo: this.myPluginFoo.bind(this),
  }

  // list the event types that this plugin cares about.
  // When the agent emits an event of these types, `MyAgentPlugin.onEvent()` will get called.
  readonly eventTypes = ['validatedMessage']

  // the event handler for the types listed in `eventTypes`
  public async onEvent(event: { type: string; data: any }, context: IRequiredContext) {
    // you can emit other events
    await context.agent.emit('my-event', { foo: event.data.id })
    // or call other agent methods that are declared in the context
    const allDIDs = await context.agent.didManagerFind()
  }

  /** {@inheritDoc IMyAgentPlugin.myPluginFoo} */
  private async myPluginFoo(args: IMyAgentPluginFooArgs, context: IRequiredContext): Promise<IMyAgentPluginFooResult> {
    // you can call other agent methods (that are declared in the `IRequiredContext`)
    const didDoc = await context.agent.resolveDid({ didUrl: args.did })
    // or emit some events
    await context.agent.emit('my-other-event', { foo: 'hello' })
    return { foobar: args.bar }
  }
}
