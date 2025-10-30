/* eslint-disable @typescript-eslint/no-explicit-any */
import {
	createMockAgent,
	resetMocks,
	mockGenerateStatusList,
	mockCreateStatusList,
	mockBroadcastStatusList,
} from './shared/bitstringStatusListMocks';
import {
	createTestDid,
	createStatusMessages,
	createPaymentConditions,
	createValidBitstringPayload,
} from './shared/bitstringStatusListHelpers';
import { CreateStatusListResult } from '../src/agent';
describe('Bitstring Status List Unit Tests', () => {
	let mockAgent: ReturnType<typeof createMockAgent>;

	beforeEach(() => {
		resetMocks();
		mockAgent = createMockAgent();
	});
	describe('cheqdGenerateStatusList Unit Tests', () => {
		it('should call with correct default parameters', async () => {
			await mockAgent.cheqdGenerateStatusList({});

			expect(mockGenerateStatusList).toHaveBeenCalledWith({});
			expect(mockGenerateStatusList).toHaveBeenCalledTimes(1);
		});
		it('should handle different encoding formats', async () => {
			const encodings = ['base64url', 'hex', 'base64'];

			for (const encoding of encodings) {
				resetMocks();
				const result = await mockAgent.cheqdGenerateStatusList({
					bitstringEncoding: encoding,
				});

				expect(mockGenerateStatusList).toHaveBeenCalledWith({
					bitstringEncoding: encoding,
				});
				expect(typeof result).toBe('string');
			}
		});
		it('should handle different status sizes', async () => {
			const statusSizes = [1, 2, 4, 8];

			for (const statusSize of statusSizes) {
				resetMocks();
				await mockAgent.cheqdGenerateStatusList({
					statusSize,
					length: 1000,
				});

				expect(mockGenerateStatusList).toHaveBeenCalledWith({
					statusSize,
					length: 1000,
				});
			}
		});
	});

	describe('cheqdCreateStatusList Unit Tests', () => {
		const baseArgs = {
			kms: 'local',
			issuerDid: createTestDid(),
			statusListName: 'unit-test-list',
			statusPurpose: 'revocation' as const,
			encrypted: false,
		};
		it('should create unencrypted status list', async () => {
			const result = (await mockAgent.cheqdCreateStatusList(baseArgs)) as CreateStatusListResult;

			expect(mockCreateStatusList).toHaveBeenCalledWith(baseArgs);
			expect(result.created).toBe(true);
			expect(result.resource.metadata.encrypted).toBe(false);
		});

		it('should create encrypted status list with payment conditions', async () => {
			const paymentConditions = createPaymentConditions();
			const encryptedArgs = {
				...baseArgs,
				encrypted: true,
				paymentConditions,
				returnSymmetricKey: true,
			};

			const result = (await mockAgent.cheqdCreateStatusList(encryptedArgs)) as CreateStatusListResult;

			expect(mockCreateStatusList).toHaveBeenCalledWith(encryptedArgs);
			expect(result.created).toBe(true);
			expect(result.resource.metadata.encrypted).toBe(true);
			expect(result.symmetricKey).toBeDefined();
		});

		it('should handle multi-bit status lists', async () => {
			const statusMessages = createStatusMessages(2);
			const multiBitArgs = {
				...baseArgs,
				statusSize: 2,
				statusMessages,
			};

			const result = (await mockAgent.cheqdCreateStatusList(multiBitArgs)) as CreateStatusListResult;

			expect(mockCreateStatusList).toHaveBeenCalledWith(multiBitArgs);
			expect(result.resource.metadata.statusSize).toBe(2);
			expect(result.resource.metadata.statusMessages).toEqual(statusMessages);
		});

		it('should handle TTL configuration', async () => {
			const ttl = 3600000; // 1 hour
			const ttlArgs = {
				...baseArgs,
				ttl,
			};

			const result = (await mockAgent.cheqdCreateStatusList(ttlArgs)) as CreateStatusListResult;

			expect(mockCreateStatusList).toHaveBeenCalledWith(ttlArgs);
			expect(result.resource.bitstringStatusListCredential.ttl).toBe(ttl);
		});

		it('should handle status reference URLs', async () => {
			const statusReference = 'https://example.com/status-meanings';
			const refArgs = {
				...baseArgs,
				statusReference,
			};

			const result = (await mockAgent.cheqdCreateStatusList(refArgs)) as CreateStatusListResult;

			expect(mockCreateStatusList).toHaveBeenCalledWith(refArgs);
			expect(result.resource.metadata.statusReference).toBe(statusReference);
		});
	});
	describe('cheqdBroadcastStatusList Unit Tests', () => {
		const baseArgs = {
			kms: 'local',
			payload: createValidBitstringPayload(),
			network: 'testnet' as any,
		};

		it('should broadcast valid payload', async () => {
			const result = await mockAgent.cheqdBroadcastStatusList(baseArgs);

			expect(mockBroadcastStatusList).toHaveBeenCalledWith(baseArgs);
			expect(result).toBe(true);
		});

		it('should handle custom fees', async () => {
			const customFee = {
				amount: [{ denom: 'ncheq', amount: '50000000' }],
				gas: '400000',
			};
			const feeArgs = {
				...baseArgs,
				fee: customFee,
			};

			const result = await mockAgent.cheqdBroadcastStatusList(feeArgs);

			expect(mockBroadcastStatusList).toHaveBeenCalledWith(feeArgs);
			expect(result).toBe(true);
		});

		it('should handle sign inputs', async () => {
			const signInputs = [
				{
					verificationMethodId: 'did:cheqd:testnet:test#key-1',
					keyType: 'Ed25519' as const,
					privateKeyHex: '0x' + Buffer.alloc(32, 1).toString('hex'),
				},
			];
			const signArgs = {
				...baseArgs,
				signInputs,
			};

			const result = await mockAgent.cheqdBroadcastStatusList(signArgs);

			expect(mockBroadcastStatusList).toHaveBeenCalledWith(signArgs);
			expect(result).toBe(true);
		});
	});
});
