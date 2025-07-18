/* eslint-disable @typescript-eslint/no-unused-vars */
import { DIDDocument } from '@veramo/core-types';
import { fromString, toString } from 'uint8arrays';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import { Cheqd, EncodedList, EncodedListAsArray, StatusOptions } from '../agent/index.js';

export function isEncodedList(list: unknown): list is EncodedList {
	return typeof list === 'string' && list.split('-').every((item) => typeof item === 'string' && item && item.length);
}

export function getEncodedList(list: unknown, validate = true): EncodedListAsArray {
	if (validate && !isEncodedList(list)) throw new Error('Invalid encoded list');
	const [symmetricEncryptionCipherText, ThresholdEncryptionCipherText] = (list as EncodedList).split('-');
	return [symmetricEncryptionCipherText, ThresholdEncryptionCipherText] as const;
}

export async function generateSymmetricKey(params?: AesKeyGenParams): Promise<CryptoKey> {
	return await crypto.subtle.generateKey(
		params || {
			name: 'AES-GCM',
			length: 256,
		},
		true,
		['encrypt', 'decrypt']
	);
}

export async function safeDeserialise<T>(
	string: string,
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	deserialiser: (string: string, ...args: any[]) => T,
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	deserialiserArgs: any[] = [],
	message?: string
): Promise<T> {
	try {
		return await deserialiser(string, ...deserialiserArgs);
	} catch (error) {
		return message
			? (function () {
					throw new Error(
						`[did-provider-cheqd]: deserialise: ${message}: ${(error as Error).message || error}`
					);
				})()
			: (function () {
					throw error;
				})();
	}
}

export async function randomFromRange(min: number, max: number, notIn: number[]): Promise<number> {
	const random = Math.floor(Math.random() * (max - min + 1) + min);
	if (notIn.includes(random)) {
		return await randomFromRange(min, max, notIn);
	}
	return random;
}

export async function randomBytes(length: number): Promise<Buffer> {
	return Buffer.from(Array.from({ length }, () => Math.floor(Math.random() * 256)));
}

export async function toBlob(data: Uint8Array): Promise<Blob> {
	return new Blob([data]);
}

export async function blobToHexString(blob: Blob): Promise<string> {
	// buffer from blob
	const buffer = await blob.arrayBuffer();

	// convert buffer to uint8Array
	const uint8Array = new Uint8Array(buffer);

	return toString(uint8Array, 'hex');
}

export async function blobToUint8Array(blob: Blob): Promise<Uint8Array> {
	const arrayBuffer = await blob.arrayBuffer();
	return new Uint8Array(arrayBuffer);
}

export function getControllers(didDocument: DIDDocument): string[] {
	const controllers: string[] = [];
	if (didDocument.controller) {
		if (typeof didDocument.controller === 'string') {
			controllers.push(didDocument.controller);
		}
		if (Array.isArray(didDocument.controller)) {
			controllers.push(...didDocument.controller);
		}
	}
	return controllers;
}

/**
 * Check if encoded bitstring is valid base64url format
 */
export function isValidEncodedBitstring(encodedList: string): boolean {
	try {
		// Should be valid base64url
		fromString(encodedList, 'base64url');
		return true;
	} catch {
		return false;
	}
}
// Enhanced encoding function that returns metadata
export async function encodeWithMetadata(
	symmetricEncryptionCiphertext: Blob,
	thresholdEncryptionCiphertext: Uint8Array
): Promise<{ encodedList: string; symmetricLength: number }> {
	const symmetricBytes = await blobToUint8Array(symmetricEncryptionCiphertext);
	// Concatenate both byte arrays
	const combinedBytes = new Uint8Array(symmetricBytes.length + thresholdEncryptionCiphertext.length);
	combinedBytes.set(symmetricBytes, 0);
	combinedBytes.set(thresholdEncryptionCiphertext, symmetricBytes.length);

	// Encode as base64url
	const encodedList = toString(combinedBytes, 'base64url');

	return { encodedList, symmetricLength: symmetricBytes.length };
}

export function decodeWithMetadata(
	encodedList: string,
	symmetricLength: number
): {
	symmetricEncryptionCiphertext: Blob;
	thresholdEncryptionCiphertext: Uint8Array;
} {
	// Decode from base64url to bytes
	const combinedBytes = fromString(encodedList, 'base64url');

	// Split based on the symmetric length
	const symmetricBytes = combinedBytes.slice(0, symmetricLength);
	const thresholdBytes = combinedBytes.slice(symmetricLength);

	// Return as desired types
	return {
		symmetricEncryptionCiphertext: new Blob([symmetricBytes]),
		thresholdEncryptionCiphertext: thresholdBytes,
	};
}

interface IndexGenerationConfig {
	statusSize?: number;
	length?: number; // Bitstring length (default: 131072)
	maxRetries?: number;
}
/**
 * Generates a random statusListIndex based on external system constraints
 *
 * @param statusOptions - Constraints from external StatusListIndexManager
 * @param config - Bitstring configuration (statusSize, length, etc.)
 * @returns Random statusListIndex that satisfies all constraints
 */
export function generateRandomStatusListIndex(
	statusOptions: StatusOptions,
	config: IndexGenerationConfig = {}
): number {
	const {
		statusSize = Cheqd.DefaultBitstringStatusSize,
		length = Cheqd.DefaultBitstringLength,
		maxRetries = 1000,
	} = config;

	// If external system already provided a specific index, validate and return it
	if (statusOptions.statusListIndex !== undefined) {
		validateStatusListIndex(statusOptions.statusListIndex, statusOptions, config);
		return statusOptions.statusListIndex;
	}

	// Calculate valid range bounds
	const bounds = calculateValidRange(statusOptions, config);
	const excludedIndices = new Set(statusOptions.indexNotIn || []);

	// Check if generation is possible
	const totalPossibleIndices = bounds.end - bounds.start + 1;
	if (excludedIndices.size >= totalPossibleIndices) {
		throw new Error(`Cannot generate index: all indices in range [${bounds.start}, ${bounds.end}] are excluded`);
	}
	let attempts = 0;
	while (attempts < maxRetries) {
		// Generate cryptographically secure random index within range
		const randBytes = cryptoRandomBytes(4);
		const randomValue = randBytes.readUInt32BE(0);

		// Map to valid range [bounds.start, bounds.end]
		const rangeSize = bounds.end - bounds.start + 1;
		const statusListIndex = bounds.start + (randomValue % rangeSize);

		// Check if this index is excluded
		if (!excludedIndices.has(statusListIndex)) {
			return statusListIndex;
		}

		attempts++;
	}

	throw new Error(
		`Failed to generate unique statusListIndex after ${maxRetries} attempts. ` +
			`Range: [${bounds.start}, ${bounds.end}], Excluded: ${excludedIndices.size} indices`
	);
}
/**
 * Validates a specific statusListIndex against constraints
 */
function validateStatusListIndex(index: number, statusOptions: StatusOptions, config: IndexGenerationConfig): void {
	const bounds = calculateValidRange(statusOptions, config);
	const excludedIndices = statusOptions.indexNotIn || [];

	if (index < bounds.start || index > bounds.end) {
		throw new Error(`StatusListIndex ${index} is outside valid range [${bounds.start}, ${bounds.end}]`);
	}

	if (excludedIndices.includes(index)) {
		throw new Error(`StatusListIndex ${index} is in the excluded list: [${excludedIndices.join(', ')}]`);
	}
}
/**
 * Calculates the valid range for statusListIndex generation
 */
function calculateValidRange(
	statusOptions: StatusOptions,
	config: IndexGenerationConfig
): { start: number; end: number } {
	const { statusSize = Cheqd.DefaultBitstringStatusSize, length = Cheqd.DefaultBitstringLength } = config;

	// Calculate maximum possible index based on bitstring configuration
	const totalBits = length * statusSize;
	const alignedLength = Math.ceil(totalBits / 8) * 8;
	const maxPossibleIndex = Math.floor(alignedLength / statusSize) - 1;

	// Start with external system's range constraints
	let start = statusOptions.statusListRangeStart ?? 0;
	let end = statusOptions.statusListRangeEnd ?? maxPossibleIndex;

	// Ensure range is within bitstring bounds
	start = Math.max(0, start);
	end = Math.min(maxPossibleIndex, end);

	// Validate range
	if (start > end) {
		throw new Error(
			`Invalid range: start (${start}) is greater than end (${end}). ` +
				`Maximum possible index for this configuration: ${maxPossibleIndex}`
		);
	}

	if (start < 0 || end > maxPossibleIndex) {
		throw new Error(
			`Range [${start}, ${end}] exceeds valid bounds [0, ${maxPossibleIndex}] ` +
				`for statusSize=${statusSize} and length=${length}`
		);
	}

	return { start, end };
}
