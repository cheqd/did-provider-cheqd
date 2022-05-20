import {
  IIdentifier,
  IKey,
  IService,
  IAgentContext,
  IKeyManager,
  ManagedKeyInfo,
} from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import Multibase from 'multibase'
import Multicodec from 'multicodec'

type IContext = IAgentContext<IKeyManager>

/**
 * You can use this template for an `AbstractIdentifierProvider` implementation.
 *
 * Implementations of this interface are used by `@veramo/did-manager` to implement
 * CRUD operations for various DID methods.
 *
 * If you wish to implement support for a particular DID method, this is the type of class
 * you need to implement.
 *
 * If you don't want to customize this, then it is safe to remove from the template.
 *
 * @alpha
 */
export class CheqdDIDProvider extends AbstractIdentifierProvider {
  private defaultKms: string

  constructor(options: { defaultKms: string }) {
    super()
    this.defaultKms = options.defaultKms
  }

  async createIdentifier(
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    { kms, alias }: { kms?: string; alias?: string },
    context: IContext,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const key: ManagedKeyInfo = await context.agent.keyManagerCreate({
      kms: kms || this.defaultKms,
      type: 'Ed25519',
    })

    const methodSpecificId = Buffer.from(
      Multibase.encode(
        'base58btc',
        Multicodec.addPrefix(
          'ed25519-pub',
          Buffer.from(key.publicKeyHex, 'hex'),
        ),
      ),
    )
      .toString()
      .substr(0, 32)

    const identifier: IIdentifier = {
      did: 'did:cheqd:mainnet:' + methodSpecificId,
      controllerKeyId: key.kid,
      keys: [key],
      services: [],
      provider: 'cheqd',
    }

    // TODO: Implement custom debugger on creation.

    return identifier
  }

  async deleteIdentifier(
    identity: IIdentifier,
    context: IContext,
  ): Promise<boolean> {
    for (const { kid } of identity.keys) {
      await context.agent.keyManagerDelete({ kid })
    }
    return true
  }

  async addKey(
    {
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
      identifier,
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
      key,
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
      options,
      //  eslint-disable-next-line @typescript-eslint/no-explicit-any
    }: { identifier: IIdentifier; key: IKey; options?: any },
    //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    context: IContext,
    //  eslint-disable-next-line @typescript-eslint/no-explicit-any
  ): Promise<any> {
    throw Error('CheqdDIDProvider addKey not supported yet.')
  }

  async addService(
    {
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
      identifier,
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
      service,
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
      options,
      //  eslint-disable-next-line @typescript-eslint/no-explicit-any
    }: { identifier: IIdentifier; service: IService; options?: any },
    //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    context: IContext,
    //  eslint-disable-next-line @typescript-eslint/no-explicit-any
  ): Promise<any> {
    throw Error('CheqdDIDProvider addService not supported yet.')
  }

  async removeKey(
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    args: {
      identifier: IIdentifier;
      kid: string;
      //  eslint-disable-next-line @typescript-eslint/no-explicit-any
      options?: any },
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    context: IContext,
      //  eslint-disable-next-line @typescript-eslint/no-explicit-any
  ): Promise<any> {
    throw Error('CheqdDIDProvider removeKey not supported yet.')
  }

  async removeService(
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    args: {
      identifier: IIdentifier;
      id: string;
      //  eslint-disable-next-line @typescript-eslint/no-explicit-any
      options?: any },
      //  eslint-disable-next-line @typescript-eslint/no-unused-vars
    context: IContext,
      //  eslint-disable-next-line @typescript-eslint/no-explicit-any
  ): Promise<any> {
    throw Error('CheqdDIDProvider removeService not supported yet.')
  }
}
