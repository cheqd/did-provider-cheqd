/* eslint-disable @typescript-eslint/no-explicit-any */
import { jest } from '@jest/globals';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { Cheqd } from '../src/agent/ICheqd.js';
import { verifyEddsaJcs2022 } from '../src/utils/eddsa-jcs-2022.js';

// Exercises the ICheqd.ts wiring (key resolution via resolveDid + extractPublicKeyHex,
// keyManagerSign call shape) that __tests__/eddsaJcs2022.test.ts cannot reach, since that file
// tests the pure crypto module directly. Only resolveDid and keyManagerSign are mocked - the
// signing/canonicalization math is the real implementation, so a bug in either the key lookup
// or the hex encoding assumption documented in signBitstringStatusListCredential would fail here.
describe('Cheqd.signBitstringStatusListCredential (wiring)', () => {
	const ISSUER_DID = 'did:example:issuer123';
	const KID = `${ISSUER_DID}#key-1`;

	function makeMockContext() {
		const { publicKey, privateKey } = generateKeyPairSync('ed25519');
		const publicKeyHex = Buffer.from((publicKey.export({ format: 'jwk' }) as any).x, 'base64url').toString('hex');

		const resolveDid = jest.fn().mockImplementation(async () => ({
			didDocument: {
				id: ISSUER_DID,
				verificationMethod: [{ id: KID, type: 'Ed25519VerificationKey2020', controller: ISSUER_DID, publicKeyHex }],
				assertionMethod: [KID],
			},
		}));
		const keyManagerSign = jest.fn().mockImplementation(async (args: any) => {
			const data = Buffer.from(args.data, 'hex');
			const signature = cryptoSign(null, data, privateKey);
			return signature.toString('hex');
		});

		const context: any = { agent: { resolveDid, keyManagerSign } };
		return {
			context,
			resolveDid,
			keyManagerSign,
			publicKeyBytes: Buffer.from((publicKey.export({ format: 'jwk' }) as any).x, 'base64url'),
		};
	}

	it('resolves the issuer key via assertionMethod and produces a verifying proof', async () => {
		const { context, resolveDid, keyManagerSign, publicKeyBytes } = makeMockContext();

		const signed = await (Cheqd as any).signBitstringStatusListCredential(
			{ type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-fake-list' },
			{ issuerDid: ISSUER_DID },
			context
		);

		expect(resolveDid).toHaveBeenCalledWith({ didUrl: ISSUER_DID });
		expect(keyManagerSign).toHaveBeenCalledWith(
			expect.objectContaining({ keyRef: expect.any(String), algorithm: 'Ed25519', encoding: 'base16' })
		);
		expect(signed.proof.verificationMethod).toBe(KID);
		expect(verifyEddsaJcs2022(signed, publicKeyBytes)).toBe(true);
	});

	it('falls back to verificationMethod[0] when assertionMethod is absent', async () => {
		const { context, publicKeyBytes } = makeMockContext();
		context.agent.resolveDid = jest.fn().mockImplementation(async () => ({
			didDocument: {
				id: ISSUER_DID,
				verificationMethod: [
					{
						id: KID,
						type: 'Ed25519VerificationKey2020',
						controller: ISSUER_DID,
						publicKeyHex: Buffer.from(publicKeyBytes).toString('hex'),
					},
				],
				// no assertionMethod
			},
		}));

		const signed = await (Cheqd as any).signBitstringStatusListCredential(
			{ type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-fake-list' },
			{ issuerDid: ISSUER_DID },
			context
		);
		expect(verifyEddsaJcs2022(signed, publicKeyBytes)).toBe(true);
	});

	it('throws if the issuer DID cannot be resolved', async () => {
		const { context } = makeMockContext();
		context.agent.resolveDid = jest.fn().mockImplementation(async () => ({ didDocument: null }));

		await expect(
			(Cheqd as any).signBitstringStatusListCredential(
				{ type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-x' },
				{ issuerDid: ISSUER_DID },
				context
			)
		).rejects.toThrow(/could not resolve/);
	});

	it('throws if the resolved DID document has no verification method', async () => {
		const { context } = makeMockContext();
		context.agent.resolveDid = jest.fn().mockImplementation(async () => ({ didDocument: { id: ISSUER_DID } }));

		await expect(
			(Cheqd as any).signBitstringStatusListCredential(
				{ type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-x' },
				{ issuerDid: ISSUER_DID },
				context
			)
		).rejects.toThrow(/no usable verification method/);
	});
});

describe('Cheqd.updateBitstringStatusListCredentialEncodedList (wiring)', () => {
	it('preserves the unsigned path unchanged when the existing proof is a JWT', async () => {
		const existing: any = {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiableCredential', 'BitstringStatusListCredential'],
			issuer: 'did:example:issuer123',
			issuanceDate: new Date().toISOString(),
			credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-old' },
			proof: { type: 'JwtProof2020', jwt: 'header.payload.signature' },
		};
		const updated = await (Cheqd as any).updateBitstringStatusListCredentialEncodedList(existing, 'u-new', undefined);
		expect(updated.credentialSubject.encodedList).toBe('u-new');
		expect(updated.proof).toBe(existing.proof); // untouched, same object - no re-sign attempted
	});

	it('re-signs when the existing proof is DataIntegrityProof / eddsa-jcs-2022', async () => {
		const { publicKey, privateKey } = generateKeyPairSync('ed25519');
		const publicKeyHex = Buffer.from((publicKey.export({ format: 'jwk' }) as any).x, 'base64url').toString('hex');
		const ISSUER_DID = 'did:example:issuer123';
		const KID = `${ISSUER_DID}#key-1`;

		const resolveDid = jest.fn().mockImplementation(async () => ({
			didDocument: {
				id: ISSUER_DID,
				verificationMethod: [{ id: KID, type: 'Ed25519VerificationKey2020', controller: ISSUER_DID, publicKeyHex }],
				assertionMethod: [KID],
			},
		}));
		const keyManagerSign = jest.fn().mockImplementation(async (args: any) => {
			const data = Buffer.from(args.data, 'hex');
			return cryptoSign(null, data, privateKey).toString('hex');
		});
		const context: any = { agent: { resolveDid, keyManagerSign } };

		const existing: any = {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiableCredential', 'BitstringStatusListCredential'],
			issuer: ISSUER_DID,
			issuanceDate: new Date().toISOString(),
			credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-old' },
			proof: {
				type: 'DataIntegrityProof',
				cryptosuite: 'eddsa-jcs-2022',
				verificationMethod: KID,
				proofValue: 'z-stale',
			},
		};
		const updated = await (Cheqd as any).updateBitstringStatusListCredentialEncodedList(existing, 'u-new', context);

		expect(updated.credentialSubject.encodedList).toBe('u-new');
		expect(updated.proof.proofValue).not.toBe('z-stale'); // actually re-signed, not just patched
		const publicKeyBytes = Buffer.from((publicKey.export({ format: 'jwk' }) as any).x, 'base64url');
		expect(verifyEddsaJcs2022(updated, publicKeyBytes)).toBe(true);
	});

	it('throws on a signedProof credential if no context is given to re-sign with', async () => {
		const existing: any = {
			issuer: 'did:example:issuer123',
			credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: 'u-old' },
			proof: {
				type: 'DataIntegrityProof',
				cryptosuite: 'eddsa-jcs-2022',
				verificationMethod: 'did:example:issuer123#key-1',
			},
		};
		await expect(
			(Cheqd as any).updateBitstringStatusListCredentialEncodedList(existing, 'u-new', undefined)
		).rejects.toThrow(/requires the agent context/);
	});
});
