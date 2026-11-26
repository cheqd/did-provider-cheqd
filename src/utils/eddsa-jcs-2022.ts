/**
 * `DataIntegrityProof` / `eddsa-jcs-2022` sign + verify for status-list credentials.
 *
 * Context: `BitstringStatusListCredential` resources are published with a JWT proof that is
 * computed BEFORE `credentialSubject.encodedList` is attached, and are updated by patching
 * `encodedList` into the existing (unchanged) proof. Neither path signs the bits a reader
 * actually trusts, so a third-party verifier that checks the list's proof before reading a bit
 * (as W3C Bitstring Status List v1.0 expects) rejects a cheqd-published list, or — if it skips
 * that check — accepts a list whose bits could have been altered in transit or by whoever serves
 * it. See https://github.com/cheqd/did-provider-cheqd/issues/657.
 *
 * This module signs the credential's FULL JSON (including `encodedList`) as a Data Integrity
 * proof, `eddsa-jcs-2022`: JCS (RFC 8785) canonicalize, SHA-256, Ed25519 over the concatenation
 * of the proof-options hash and the document hash, `proofValue` as `z` + base58btc. The exact
 * construction is read from `@kya-os/mcp`'s verifier
 * (https://www.npmjs.com/package/@kya-os/mcp, `card/proof/status-list-proof.ts`) so a credential
 * signed here verifies against their ready `createStatusListProofVerifier`, not just a
 * self-consistent check — see this package's test suite for a cross-check against it.
 *
 * All crypto outside of hashing and canonicalization is injected: this module never touches a
 * private key. The caller supplies `sign` (bound to whichever KMS holds the issuer's key) and,
 * for verification, the issuer's resolved public key bytes.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';

export const DATA_INTEGRITY_PROOF_TYPE = 'DataIntegrityProof';
export const EDDSA_JCS_2022_CRYPTOSUITE = 'eddsa-jcs-2022';
const ED25519_SIGNATURE_LENGTH = 64;
const ED25519_PUBLIC_KEY_LENGTH = 32;

/** Base58 (Bitcoin alphabet), used for the `z`-prefixed base58btc multibase `proofValue`. */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_ALPHABET_MAP = new Map(Array.from(BASE58_ALPHABET).map((char, i) => [char, i]));

export function base58Encode(bytes: Uint8Array): string {
	if (bytes.length === 0) return '';
	let num = 0n;
	for (const byte of bytes) num = num * 256n + BigInt(byte);
	let out = '';
	while (num > 0n) {
		out = BASE58_ALPHABET[Number(num % 58n)] + out;
		num /= 58n;
	}
	for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
	return out;
}

export function base58Decode(encoded: string): Uint8Array {
	if (encoded.length === 0) return new Uint8Array(0);
	let num = 0n;
	for (const char of encoded) {
		const value = BASE58_ALPHABET_MAP.get(char);
		if (value === undefined) throw new Error(`[did-provider-cheqd]: invalid base58 character: ${char}`);
		num = num * 58n + BigInt(value);
	}
	let hex = num === 0n ? '' : num.toString(16);
	if (hex.length % 2 === 1) hex = `0${hex}`;
	let leadingZeros = 0;
	for (const char of encoded) {
		if (char !== '1') break;
		leadingZeros++;
	}
	const out = new Uint8Array(leadingZeros + hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		out[leadingZeros + i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return out;
}

function sha256(bytes: Uint8Array): Uint8Array {
	return new Uint8Array(createHash('sha256').update(bytes).digest());
}

/** A JSON object with at most one top-level `proof` member, as any W3C VC credential is. */
export type JsonCredential = Record<string, unknown> & { proof?: unknown };

export interface DataIntegrityProofOptions {
	/** DID URL of the verification method whose key will sign (and must verify) the proof. */
	verificationMethod: string;
	/** Defaults to now. Injectable for deterministic tests. */
	created?: string;
}

/**
 * The bytes a signer must sign, and a verifier must recompute: the proof options (without
 * `proofValue`, with the document's `@context` folded in) and the document (without `proof`),
 * each JCS-canonicalized and SHA-256 hashed, concatenated proof-hash-then-document-hash.
 */
export function eddsaJcs2022SigningInput(document: JsonCredential, proofOptions: Record<string, unknown>): Uint8Array {
	const unsecuredDocument = { ...document };
	delete unsecuredDocument.proof;
	const options = { ...proofOptions };
	if (unsecuredDocument['@context'] !== undefined) {
		options['@context'] = unsecuredDocument['@context'];
	}
	const encoder = new TextEncoder();
	const proofHash = sha256(encoder.encode(canonicalize(options)));
	const documentHash = sha256(encoder.encode(canonicalize(unsecuredDocument)));
	const signingInput = new Uint8Array(proofHash.length + documentHash.length);
	signingInput.set(proofHash, 0);
	signingInput.set(documentHash, proofHash.length);
	return signingInput;
}

/**
 * Sign `document` (which MUST already carry every field a verifier should trust, including
 * `credentialSubject.encodedList` — this module does not care what the document contains, only
 * that it signs it as given) and return it with a `DataIntegrityProof` / `eddsa-jcs-2022` proof
 * attached. `sign` receives the raw signing input and MUST return a raw 64-byte Ed25519
 * signature (not JWS- or JWT-framed) — bind it to the issuer's KMS-held key before calling.
 */
export async function signEddsaJcs2022<T extends JsonCredential>(
	document: T,
	options: DataIntegrityProofOptions,
	sign: (data: Uint8Array) => Promise<Uint8Array>
): Promise<T & { proof: Record<string, unknown> }> {
	const proofOptions = {
		type: DATA_INTEGRITY_PROOF_TYPE,
		cryptosuite: EDDSA_JCS_2022_CRYPTOSUITE,
		created: options.created ?? new Date().toISOString(),
		verificationMethod: options.verificationMethod,
		proofPurpose: 'assertionMethod',
	};
	const signingInput = eddsaJcs2022SigningInput(document, proofOptions);
	const signature = await sign(signingInput);
	if (signature.length !== ED25519_SIGNATURE_LENGTH) {
		throw new Error(
			`[did-provider-cheqd]: eddsa-jcs-2022 signer returned ${signature.length} bytes, expected ${ED25519_SIGNATURE_LENGTH}`
		);
	}
	return {
		...document,
		proof: { ...proofOptions, proofValue: `z${base58Encode(signature)}` },
	};
}

/**
 * Verify a `DataIntegrityProof` / `eddsa-jcs-2022` proof on `document` against the issuer's
 * raw 32-byte Ed25519 public key. Returns `false` (never throws) on any malformed input, wrong
 * proof type/cryptosuite/purpose, or bad signature — callers MUST treat `false` as fail-closed
 * (an unverifiable list reads as not fit to trust, per the same rule KYA-OS's own verifier uses).
 */
export function verifyEddsaJcs2022(document: JsonCredential, issuerPublicKey: Uint8Array): boolean {
	try {
		const proof = document.proof as Record<string, unknown> | undefined;
		if (!proof || typeof proof !== 'object') return false;
		if (proof.type !== DATA_INTEGRITY_PROOF_TYPE || proof.cryptosuite !== EDDSA_JCS_2022_CRYPTOSUITE) return false;
		if (proof.proofPurpose !== 'assertionMethod') return false;
		const { proofValue } = proof;
		if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) return false;
		if (issuerPublicKey.length !== ED25519_PUBLIC_KEY_LENGTH) return false;

		const signature = base58Decode(proofValue.slice(1));
		if (signature.length !== ED25519_SIGNATURE_LENGTH) return false;

		const proofOptions = { ...proof };
		delete proofOptions.proofValue;
		const signingInput = eddsaJcs2022SigningInput(document, proofOptions);

		return verifyRawEd25519(issuerPublicKey, signingInput, signature);
	} catch {
		return false;
	}
}

/** Raw Ed25519 verification via a SPKI-wrapped DER key, so only `node:crypto` is needed. */
function verifyRawEd25519(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
	// The fixed 12-byte SPKI prefix for an Ed25519 (OID 1.3.101.112) public key; the 32-byte raw
	// key follows verbatim. Avoids pulling in a JWK/multicodec dependency for one conversion.
	const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
	const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]);
	const keyObject = createPublicKey({ key: spki, format: 'der', type: 'spki' });
	return cryptoVerify(null, Buffer.from(data), keyObject, Buffer.from(signature));
}
