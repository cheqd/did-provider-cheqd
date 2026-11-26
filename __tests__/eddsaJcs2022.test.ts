import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
	signEddsaJcs2022,
	verifyEddsaJcs2022,
	base58Encode,
	base58Decode,
	DATA_INTEGRITY_PROOF_TYPE,
	EDDSA_JCS_2022_CRYPTOSUITE,
} from '../src/utils/eddsa-jcs-2022.js';
// Cross-verifies against @kya-os/mcp's real, unmodified verifier - not just this module's own
// (self-consistent but potentially both-wrong) round trip. See
// https://github.com/cheqd/did-provider-cheqd/issues/657#issuecomment-6611910023.
import { createStatusListProofVerifier } from '@kya-os/mcp/card';

const DID = 'did:example:issuer123';
const KID = `${DID}#key-1`;

function makeSigner() {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const rawPublicKey = (publicKey.export({ format: 'jwk' }) as { x: string }).x;
	const publicKeyBytes = Buffer.from(rawPublicKey, 'base64url');
	const sign = async (data: Uint8Array) => cryptoSign(null, data, privateKey);
	return { publicKeyBytes, publicKeyJwk: publicKey.export({ format: 'jwk' }), sign };
}

function makeCredential(encodedList: string) {
	return {
		'@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
		id: 'https://example.com/status-lists/1',
		type: ['VerifiableCredential', 'StatusList2021Credential'],
		issuer: DID,
		issuanceDate: new Date().toISOString(),
		credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList },
	};
}

describe('base58Encode / base58Decode', () => {
	it('round-trips arbitrary bytes', () => {
		const samples = [new Uint8Array(0), new Uint8Array([0]), new Uint8Array([0, 0, 1]), crypto.getRandomValues(new Uint8Array(64))];
		for (const bytes of samples) {
			expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
		}
	});

	it('rejects an invalid character', () => {
		expect(() => base58Decode('0')).toThrow(); // '0' is excluded from the Bitcoin alphabet
	});
});

describe('signEddsaJcs2022 / verifyEddsaJcs2022', () => {
	it('produces a proof that verifies', async () => {
		const { publicKeyBytes, sign } = makeSigner();
		const signed = await signEddsaJcs2022(makeCredential('u-fake-encoded-list'), { verificationMethod: KID }, sign);

		expect(signed.proof.type).toBe(DATA_INTEGRITY_PROOF_TYPE);
		expect(signed.proof.cryptosuite).toBe(EDDSA_JCS_2022_CRYPTOSUITE);
		expect((signed.proof.proofValue as string).startsWith('z')).toBe(true);
		expect(verifyEddsaJcs2022(signed, publicKeyBytes)).toBe(true);
	});

	it('rejects a tampered encodedList', async () => {
		const { publicKeyBytes, sign } = makeSigner();
		const signed = await signEddsaJcs2022(makeCredential('u-fake-encoded-list'), { verificationMethod: KID }, sign);
		const tampered = { ...signed, credentialSubject: { ...signed.credentialSubject, encodedList: 'u-ALTERED' } };
		expect(verifyEddsaJcs2022(tampered, publicKeyBytes)).toBe(false);
	});

	it('rejects a credential signed by a different key', async () => {
		const { sign } = makeSigner();
		const other = makeSigner();
		const signed = await signEddsaJcs2022(makeCredential('u-fake-encoded-list'), { verificationMethod: KID }, sign);
		expect(verifyEddsaJcs2022(signed, other.publicKeyBytes)).toBe(false);
	});

	it('rejects an unsigned credential', () => {
		expect(verifyEddsaJcs2022(makeCredential('u-fake-encoded-list'), new Uint8Array(32))).toBe(false);
	});

	it('rejects a non-DataIntegrityProof proof', () => {
		const credential = { ...makeCredential('u-fake-encoded-list'), proof: { type: 'Ed25519Signature2020', proofValue: 'zabc' } };
		expect(verifyEddsaJcs2022(credential, new Uint8Array(32))).toBe(false);
	});

	it('throws if the injected signer returns the wrong signature length', async () => {
		await expect(
			signEddsaJcs2022(makeCredential('u-x'), { verificationMethod: KID }, async () => new Uint8Array(10))
		).rejects.toThrow(/64/);
	});

	it('round-trips against @kya-os/mcp\'s real createStatusListProofVerifier', async () => {
		const { publicKeyJwk, sign } = makeSigner();
		const signed = await signEddsaJcs2022(makeCredential('u-fake-encoded-list'), { verificationMethod: KID }, sign);

		const didResolver = {
			async resolve(did: string) {
				if (did !== DID) return null;
				return { id: DID, verificationMethod: [{ id: KID, type: 'JsonWebKey2020', controller: DID, publicKeyJwk }] };
			},
		};
		const verify = createStatusListProofVerifier({ didResolver });
		await expect(verify(signed)).resolves.toBe(true);
	});
});
