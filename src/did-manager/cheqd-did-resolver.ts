import {
  DIDResolutionOptions,
  DIDResolutionResult,
  DIDResolver,
  ParsedDID,
  Resolvable,
} from 'did-resolver'

/* interface Options {
    resolver: Resolvable
} */

export function getResolver(resolverUrl?: string): Record<string, DIDResolver> {
  if (resolverUrl) return new CheqdDidResolver(resolverUrl).build()

  return new CheqdDidResolver().build()
}

export class CheqdDidResolver {
  private resolverUrl: undefined | string =
    'https://resolver.cheqd.net/1.0/identifiers/'

  constructor(resolverUrl?: string) {
    if (resolverUrl) this.resolverUrl = resolverUrl
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
