import {
	DIDDocument,
	DIDResolutionOptions,
	DIDResolutionResult,
	DIDResolver,
	ParsedDID,
	Resolvable,
} from 'did-resolver';

interface Options {
	url: string;
}

/**
 * Default resolver url.
 * @public
 */
export const DefaultResolverUrl = 'https://resolver.cheqd.net/1.0/identifiers/';

/**
 * Creates a CheqdDIDResolver instance that can be used with `did-resolver`.
 * @public
 */
export function getResolver(options?: Options): Record<string, DIDResolver> {
	if (options?.url) return new CheqdDidResolver(options).build();

	return new CheqdDidResolver().build();
}

/**
 * CheqdDIDResolver instance that can be used with `did-resolver`.
 * @public
 */
export class CheqdDidResolver {
	private resolverUrl = DefaultResolverUrl;

	constructor(options?: Options) {
		if (options?.url) this.resolverUrl = options.url;
	}

	async resolve(
		did: string,
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		parsed: ParsedDID,
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		_unused: Resolvable,
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		options: DIDResolutionOptions
	): Promise<DIDResolutionResult> {
		try {
			const result = await fetch(this.resolverUrl + did, {
				headers: { Accept: options?.accept || 'application/did+json' },
				keepalive: options.keepAlive,
			});
			const response = await result.json();
			// Check if response is a raw DID document (returned when Accept: application/did+json)
			// or a full DIDResolutionResult (returned when Accept: application/ld+json;profile="...")
			if (!('didDocument' in response)) {
				// Raw DID document - wrap it in a DIDResolutionResult
				return {
					didDocument: response as DIDDocument,
					didDocumentMetadata: {},
					didResolutionMetadata: { contentType: options?.accept || 'application/did+json' },
				};
			}

			return response as DIDResolutionResult;
		} catch (e) {
			return Promise.reject(e);
		}
	}

	build(): Record<string, DIDResolver> {
		return { cheqd: this.resolve.bind(this) };
	}
}
