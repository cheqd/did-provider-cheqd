import {
  DIDResolutionOptions,
  DIDResolutionResult,
  DIDResolver,
  ParsedDID,
  Resolvable,
} from 'did-resolver'

interface Options {
  url: string
}

/**
 * Default resolver url.
 * @public
 */
export const resolverUrl = 'https://resolver.cheqd.net/1.0/identifiers/'

/**
 * Creates a CheqdDIDResolver instance that can be used with `did-resolver`.
 * @public
 */
export function getResolver(options?: Options): Record<string, DIDResolver> {
  if (options?.url) return new CheqdDidResolver(options).build()

  return new CheqdDidResolver().build()
}

/**
 * CheqdDIDResolver instance that can be used with `did-resolver`.
 * @public
 */
export class CheqdDidResolver {
  private resolverUrl = resolverUrl

  constructor(options?: Options) {
    if (options?.url) this.resolverUrl = options.url
  }

  async resolve(
    did: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    parsed: ParsedDID,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _unused: Resolvable,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    options: DIDResolutionOptions,
  ): Promise<DIDResolutionResult> {
    try {
      const result = await fetch(this.resolverUrl + did, {
        headers: { 'Content-Type': 'application/did+json' },
      })
      const ddo = (await result.json()) as DIDResolutionResult
      return ddo
    } catch (e) {
      return Promise.reject(e)
    }
  }

  build(): Record<string, DIDResolver> {
    return { cheqd: this.resolve.bind(this) }
  }
}
