/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { jest } from '@jest/globals';
import { BitstringStatusList } from '../../src/agent';

/**
 * Mock implementations for testing Bitstring Status List functions
 */

export const mockGenerateStatusList = jest.fn().mockImplementation((args: any) => {
	const { length = 131072, statusSize = 2, bitstringEncoding = 'base64url' } = args;

	// Simulate bitstring generation
	const mockBitstring = 'eNrbuRgAAhcB2g'; // Mock base64url encoded bitstring

	switch (bitstringEncoding) {
		case 'hex':
			return Promise.resolve('deadbeef123456789abcdef');
		case 'base64':
			return Promise.resolve('eNrbuRgAAhcB2g==');
		case 'base64url':
		default:
			return Promise.resolve(mockBitstring);
	}
});
export const mockCreateStatusList = jest.fn().mockImplementation((args: any) => {
	const {
		statusPurpose,
		encrypted = false,
		statusSize = 2,
		statusMessages,
		ttl,
		statusReference,
		validUntil,
		returnSymmetricKey = false,
	} = args;

	const mockResource : BitstringStatusList = {
		bitstringStatusListCredential: {
			credentialSubject: {
				type: 'BitstringStatusListCredential',
				statusPurpose,
				encodedList: encrypted ? 'encrypted-data-hash-threshold-data' : 'eNrbuRgAAhcB2g',
				ttl,
			},
			validFrom: new Date().toISOString(),
			validUntil,
			issuer: args.issuerDid,
			'@context': [
				'https://www.w3.org/2018/credentials/v1',
				'https://w3id.org/vc/status-list/2021/v1',
			],
			proof: {},
			type: ['VerifiableCredential', 'BitstringStatusListCredential'],
			issuanceDate: new Date().toISOString(),
			id: `did:cheqd:testnet:${args.issuerDid.split(':').pop()}/resources/mock-resource-id`,
		},
		metadata: {
			encrypted,
			encoding: 'base64url',
			length: 131072,
			statusSize,
			statusReference,
			statusMessages,
			...(encrypted && { statusListHash: 'mock-hash' }),
		},
	};

	return Promise.resolve({
		created: true,
		resource: mockResource,
		resourceMetadata: {
			resourceURI: `did:cheqd:testnet:${args.issuerDid.split(':').pop()}/resources/mock-resource-id`,
			resourceCollectionId: args.issuerDid.split(':').pop(),
			resourceId: 'mock-resource-id',
			resourceName: args.statusListName,
			resourceType: 'BitstringStatusListCredential',
			mediaType: 'application/json',
			created: new Date().toISOString(),
			checksum: 'mock-checksum',
			previousVersionId: null,
			nextVersionId: null,
		},
		encrypted,
		...(encrypted && returnSymmetricKey && { symmetricKey: 'mock-symmetric-key' }),
	});
});

export const mockBroadcastStatusList = jest.fn().mockImplementation((args: any) => {
	// Simulate successful broadcast
	return Promise.resolve(true);
});
/**
 * Mock agent factory for testing
 */
export const createMockAgent = () => ({
	cheqdGenerateStatusList: mockGenerateStatusList,
	cheqdCreateStatusList: mockCreateStatusList,
	cheqdBroadcastStatusList: mockBroadcastStatusList,
});

/**
 * Helper to reset all mocks
 */
export const resetMocks = () => {
	mockGenerateStatusList.mockClear();
	mockCreateStatusList.mockClear();
	mockBroadcastStatusList.mockClear();
};
