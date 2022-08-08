import { DIDResolver } from 'did-resolver'

interface Options {
  url: string
}

/**
 * @deprecated please use `getUniresolver(url)` or `getUniresolverFor(methods, url)` instead
 */
export class CheqdUniversalResolver {
  constructor(options: Options) {
    return getUniversalResolver(options.url)
  }
}

/**
 * Creates a DIDResolver instance that can be used with `did-resolver`
 *
 * @example
 * ```typescript
 * const uniResolver = getUniversalResolver()
 * const resolver = new Resolver({
 *   web: uniResolver,
 *   key: uniResolver,
 *   elem: uniResolver
 * })
 * ```
 *
 * @param url the URL for the universal resolver instance (See https://uniresolver.io )
 * @returns `DIDResolver`
 * @public
 */
export function getUniversalResolver(
  url = 'https://resolver.cheqd.net/1.0/identifiers/',
): DIDResolver {
  if (!url) {
    throw Error('[did-resolver] Universal: url required')
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const resolve: DIDResolver = async (didUrl: string): Promise<any> => {
    try {
      const result = await fetch(url + didUrl, {
        headers: { 'Content-Type': 'application/did+ld+json' },
      })
      const ddo = await result.json()
      return ddo
    } catch (e) {
      return Promise.reject(e)
    }
  }

  return resolve
}

/**
 * Creates a mapping of DID methods to a DIDResolver instance that can be used with `did-resolver`
 *
 * @example
 * ```typescript
 * const uniResolver = getUniversalResolverFor(['web', 'key', 'elem'])
 * const resolver = new Resolver({
 *   ...uniResolver,
 *   // other resolvers
 * })
 * ```
 *
 * @param methods an array of DID methods that should be resolved by this universal resolver
 * @param url the URL for the universal resolver instance (See https://uniresolver.io )
 * @returns `Record<string, DIDResolver>` a mapping of the given methods to an instance of `DIDResolver`
 */
export function getUniversalResolverFor(
  methods: string[],
  url = 'https://resolver.cheqd.net/1.0/identifiers/',
): Record<string, DIDResolver> {
  const uniResolver = getUniversalResolver(url)
  const mapping: Record<string, DIDResolver> = {}
  for (const method of methods) {
    mapping[method] = uniResolver
  }
  return mapping
}
