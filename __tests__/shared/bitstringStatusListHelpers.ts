/* eslint-disable @typescript-eslint/no-explicit-any */
import { ICheqd } from '../../src/agent/ICheqd';
import { TAgent, IMessageHandler } from '@veramo/core-types';

type ConfiguredAgent = TAgent<ICheqd & IMessageHandler>;

/**
 * Helper function to create a valid test DID for use in tests
 */
export const createTestDid = (network: 'testnet' | 'mainnet' = 'testnet'): string => {
	const uuid = '7bf81a20-633c-4cc7-bc4a-5a45801005e0';
	return `did:cheqd:${network}:${uuid}`;
};

/**
 * Helper function to create valid status messages for multi-bit status lists
 */
export const createStatusMessages = (bitSize: number) => {
	const messageCount = Math.pow(2, bitSize);
	return Array.from({ length: messageCount }, (_, i) => ({
		status: `0x${i.toString(16).toLowerCase()}`,
		message: `Status ${i}`,
	}));
};
/**
 * Helper function to create valid payment conditions for encrypted status lists
 */
export const createPaymentConditions = () => [
	{
		feePaymentAddress: 'cheqd1fgx53ljztenl0apdhns65gjmptxvdtpqx8t3qy',
		feePaymentAmount: '1000000ncheq',
		intervalInSeconds: 3600,
		type: 'timelockPayment' as const,
	},
];
/**
 * Helper function to create a valid bitstring status list payload
 */
export const createValidBitstringPayload = (overrides?: any) => ({
	collectionId: '7bf81a20-633c-4cc7-bc4a-5a45801005e0',
	id: 'test-resource-id',
	name: 'Test Bitstring Status List',
	resourceType: 'BitstringStatusListCredential',
	version: '1.0.0',
	data: new Uint8Array(
		Buffer.from(
			JSON.stringify({
				encodedList: 'eNrbuRgAAhcB2g',
				statusPurpose: 'revocation',
				validFrom: new Date().toISOString(),
				metadata: {
					type: 'BitstringStatusListCredential',
					encrypted: false,
					encoding: 'base64url',
				},
				...overrides?.bitstringData,
			})
		)
	),
	mediaType: 'application/json',
	alsoKnownAs: [],
	...overrides,
});
/**
 * Helper function to validate bitstring status list structure
 */
export const validateBitstringStatusList = (resource: any) => {
	expect(resource).toBeDefined();
	expect(resource.statusPurpose).toBeDefined();
	expect(resource.encodedList).toBeDefined();
	expect(resource.validFrom).toBeDefined();
	expect(resource.metadata).toBeDefined();
	expect(resource.metadata.type).toBe('BitstringStatusListCredential');
	expect(resource.metadata.encrypted).toBeDefined();
	expect(resource.metadata.encoding).toBeDefined();
};
/**
 * Helper function to generate unique test names
 */
export const generateTestName = (prefix: string): string => {
	const timestamp = Date.now();
	const random = Math.floor(Math.random() * 1000);
	return `${prefix}-${timestamp}-${random}`;
};
/**
 * Helper function to wait for async operations
 */
export const waitFor = (ms: number): Promise<void> => {
	return new Promise((resolve) => setTimeout(resolve, ms));
};
/**
 * Helper function to retry operations with exponential backoff
 */
export const retryOperation = async <T>(
	operation: () => Promise<T>,
	maxRetries: number = 3,
	baseDelay: number = 1000
): Promise<T> => {
	let lastError: Error;

	for (let i = 0; i < maxRetries; i++) {
		try {
			return await operation();
		} catch (error) {
			lastError = error as Error;

			if (i < maxRetries - 1) {
				const delay = baseDelay * Math.pow(2, i);
				await waitFor(delay);
			}
		}
	}

	throw lastError!;
};
/**
 * Helper function to create test configuration
 */
export const createTestConfig = () => ({
	kms: 'local',
	network: 'testnet' as const,
	issuerDid: createTestDid('testnet'),
	fee: {
		amount: [{ denom: 'ncheq', amount: '50000000' }],
		gas: '400000',
	},
});
/**
 * Helper function to validate agent methods
 */
export const validateAgentMethods = (agent: ConfiguredAgent) => {
	const requiredMethods = ['cheqdGenerateStatusList', 'cheqdCreateStatusList', 'cheqdBroadcastStatusList'];

	for (const method of requiredMethods) {
		if (typeof agent[method] !== 'function') {
			throw new Error(`Agent missing required method: ${method}`);
		}
	}
};
/**
 * Helper function to measure operation performance
 */
export const measurePerformance = async <T>(
	operation: () => Promise<T>,
	name: string
): Promise<{ result: T; duration: number }> => {
	const startTime = Date.now();
	const result = await operation();
	const duration = Date.now() - startTime;

	console.log(`${name} completed in ${duration}ms`);

	return { result, duration };
};
