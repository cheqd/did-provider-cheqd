/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, @typescript-eslint/no-non-null-assertion */
// any is used for extensibility
// unused vars are kept by convention
// non-null assertion is used when we know better than the compiler that the value is not null or undefined
import {
	CheqdNetwork,
	DIDDocument,
	DidStdFee,
	IKeyPair,
	ISignInputs,
	MethodSpecificIdAlgo,
	ResourceModule,
	VerificationMethods,
	createDidPayload,
	createDidVerificationMethod,
	createKeyPairBase64,
	createKeyPairHex,
	createVerificationKeys,
} from '@cheqd/sdk';
import { Coin, DeliverTxResponse } from '@cosmjs/stargate';
import {
	IAgentContext,
	IKeyManager,
	IAgentPlugin,
	IPluginMethodMap,
	IAgentPluginSchema,
	IIdentifier,
	VerifiableCredential,
	IVerifyCredentialArgs,
	IVerifyResult,
	VerifiablePresentation,
	IVerifyPresentationArgs,
	IError,
	ICreateVerifiableCredentialArgs,
	ICredentialIssuer,
	IDIDManager,
	IDataStore,
	IResolver,
	W3CVerifiableCredential,
	ICredentialVerifier,
	DIDResolutionResult,
	CredentialStatusReference,
} from '@veramo/core';
import {
	CheqdDIDProvider,
	LinkedResource,
	TImportableEd25519Key,
	ResourcePayload,
	StatusList2021ResourcePayload,
	DefaultRESTUrls,
	DefaultStatusListEncodings,
	DefaultStatusList2021ResourceTypes,
	DefaultStatusList2021StatusPurposeTypes,
	DefaultStatusListEncoding,
	DefaultStatusList2021ResourceType,
	DefaultStatusList2021StatusPurposeType,
	BitstringStatusPurposeTypes,
	TPublicKeyEd25519,
	BitstringStatusListResourceType,
	BitstringStatusListPurposeType,
	BitstringStatusListResourcePayload,
} from '../did-manager/cheqd-did-provider.js';
import { fromString, toString } from 'uint8arrays';
import { decodeJWT } from 'did-jwt';
import { StatusList } from '@digitalbazaar/vc-status-list';
import { Bitstring as DBBitstring } from '@digitalbazaar/bitstring';
import { v4 } from 'uuid';
import fs from 'fs';
import Debug from 'debug';
import {
	CosmosAccessControlCondition,
	CreateCapacityDelegationAuthSignatureResult,
	LitCompatibleCosmosChain,
	LitCompatibleCosmosChains,
	LitNetwork,
	LitProtocol,
	MintCapacityCreditsResult,
} from '../dkg-threshold/lit-protocol/v6.js';
import {
	blobToHexString,
	decodeWithMetadata,
	encodeWithMetadata,
	generateRandomStatusListIndex,
	getEncodedList,
	isEncodedList,
	isValidEncodedBitstring,
	randomFromRange,
	safeDeserialise,
	toBlob,
} from '../utils/helpers.js';
import { DefaultResolverUrl } from '../did-manager/cheqd-did-resolver.js';
import { AlternativeUri } from '@cheqd/ts-proto/cheqd/resource/v2/resource.js';
import { LitNetworksV2, LitProtocolV2 } from '../dkg-threshold/lit-protocol/v2.js';

const debug = Debug('veramo:did-provider-cheqd');

export type IContext = IAgentContext<
	IDIDManager & IKeyManager & IDataStore & IResolver & ICredentialIssuer & ICredentialVerifier & ICheqd
>;
export type TExportedDIDDocWithKeys = { didDoc: DIDDocument; keys: TImportableEd25519Key[]; versionId?: string };
export type TExportedDIDDocWithLinkedResourceWithKeys = TExportedDIDDocWithKeys & { linkedResource: LinkedResource };
export type LinkedResourceMetadataResolutionResult = {
	resourceURI: string;
	resourceCollectionId: string;
	resourceId: string;
	resourceName: string;
	resourceType: string;
	mediaType: string;
	resourceVersion?: string;
	created: string;
	checksum: string;
	previousVersionId: string | null;
	nextVersionId: string | null;
};
export type DIDMetadataDereferencingResult = {
	'@context': 'https://w3id.org/did-resolution/v1';
	dereferencingMetadata: {
		contentType: string;
		error?: string;
		retrieved: string;
		did: { didString: string; methodSpecificId: string; method: string };
	};
	contentStream: {
		created: string;
		versionId: string;
		linkedResourceMetadata: LinkedResourceMetadataResolutionResult[];
	};
	contentMetadata: Record<string, any>;
};
export type ShallowTypedTx = {
	body: {
		messages: any[];
		memo: string;
		timeout_height: string;
		extension_options: any[];
		non_critical_extension_options: any[];
	};
	auth_info: {
		signer_infos: {
			public_key: { '@type': string; key: string };
			mode_info: { single: { mode: string } };
			sequence: string;
		}[];
		fee: { amount: Coin[]; gas_limit: string; payer: string; granter: string };
		tip: any | null;
	};
	signatures: string[];
};
export type ShallowTypedTxTxResponses = {
	height: string;
	txhash: string;
	codespace: string;
	code: number;
	data: string;
	raw_log: string;
	logs: any[];
	info: string;
	gas_wanted: string;
	gas_used: string;
	tx: ShallowTypedTx;
	timestamp: string;
	events: any[];
};
export type ShallowTypedTxsResponse =
	| { txs: ShallowTypedTx[]; tx_responses: ShallowTypedTxTxResponses[]; pagination: string | null; total: string }
	| undefined;
export type BlockResponse = { block_id: BlockID; block: Block; sdk_block: Block };
export type Block = { header: Header; data: Data; evidence: Evidence; last_commit: LastCommit };
export type Data = { txs: any[] };
export type Evidence = { evidence: any[] };
export type Header = {
	version: Version;
	chain_id: string;
	height: string;
	time: string;
	last_block_id: BlockID;
	last_commit_hash: string;
	data_hash: string;
	validators_hash: string;
	next_validators_hash: string;
	consensus_hash: string;
	app_hash: string;
	last_results_hash: string;
	evidence_hash: string;
	proposer_address: string;
};
export type BlockID = { hash: string; part_set_header: PartSetHeader };
export type PartSetHeader = { total: number; hash: string };
export type Version = { block: string; app: string };
export type LastCommit = { height: string; round: number; block_id: BlockID; signatures: Signature[] };
export type Signature = { block_id_flag: string; validator_address?: string; timestamp: Date; signature?: string };
export type VerificationResult = {
	verified: boolean;
	revoked?: boolean;
	suspended?: boolean;
	error?: IVerifyResult['error'];
};
export interface BitstringValidationResult {
	status: number; // e.g., 0x0, 0x1, 0x2
	purpose: string; // e.g., 'revocation', 'suspension'
	valid: boolean;
	message?: string;
}
export type BitstringVerificationResult = VerificationResult & BitstringValidationResult;
export type EncryptionResult = {
	symmetricEncryptionCiphertext: string;
	thresholdEncryptionCiphertext: string;
	stringHash: string;
	symmetricKey: string;
};
export type StatusCheckResult = { revoked?: boolean; suspended?: boolean; error?: IError };
export type BitstringUpdateResult = {
	updated: boolean;
	statusValue: BitstringStatusValue;
	previousStatusValue?: BitstringStatusValue;
	statusMessage?: string; // Human-readable status message
	error?: IError;
	statusList?: BitstringStatusList;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type BulkBitstringUpdateResult = {
	updated: boolean[];
	statusValues: BitstringStatusValue[];
	previousStatusValues?: BitstringStatusValue[];
	statusMessages?: string[]; // Human-readable status message
	error?: IError;
	statusList?: BitstringStatusList;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type RevocationResult = {
	revoked: boolean;
	error?: IError;
	statusList?: StatusList2021Revocation;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type BulkRevocationResult = {
	revoked: boolean[];
	error?: IError;
	statusList?: StatusList2021Revocation;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type SuspensionResult = {
	suspended: boolean;
	error?: IError;
	statusList?: StatusList2021Suspension;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type BulkSuspensionResult = {
	suspended: boolean[];
	error?: IError;
	statusList?: StatusList2021Suspension;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type UnsuspensionResult = {
	unsuspended: boolean;
	error?: IError;
	statusList?: StatusList2021Suspension;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type BulkUnsuspensionResult = {
	unsuspended: boolean[];
	error?: IError;
	statusList?: StatusList2021Suspension;
	symmetricKey?: string;
	published?: boolean;
	resourceMetadata?: LinkedResourceMetadataResolutionResult;
};
export type Bitstring = string;
export type SymmetricEncryptionCipherText = string;
export type ThresholdEncryptionCipherText = string;
export type EncodedList = `${SymmetricEncryptionCipherText}-${ThresholdEncryptionCipherText}` | string;
export type EncodedListAsArray = [SymmetricEncryptionCipherText, ThresholdEncryptionCipherText];
export type StatusList2021Revocation = {
	StatusList2021: {
		statusPurpose: typeof DefaultStatusList2021StatusPurposeTypes.revocation;
		encodedList: EncodedList;
		validFrom: string;
		validUntil?: string;
	};
	metadata: {
		type: typeof DefaultStatusList2021ResourceTypes.revocation;
		encrypted: boolean;
		encoding: DefaultStatusListEncoding;
		statusListHash?: string;
		paymentConditions?: PaymentCondition[];
	};
};
export type StatusList2021Suspension = {
	StatusList2021: {
		statusPurpose: typeof DefaultStatusList2021StatusPurposeTypes.suspension;
		encodedList: EncodedList;
		validFrom: string;
		validUntil?: string;
	};
	metadata: {
		type: typeof DefaultStatusList2021ResourceTypes.suspension;
		encrypted: boolean;
		encoding: DefaultStatusListEncoding;
		statusListHash?: string;
		paymentConditions?: PaymentCondition[];
	};
};
export type StatusList2021RevocationNonMigrated = {
	StatusList2021: {
		statusPurpose: typeof DefaultStatusList2021StatusPurposeTypes.revocation;
		encodedList: string;
		validFrom: string;
		validUntil?: string;
	};
	metadata: {
		type: typeof DefaultStatusList2021ResourceTypes.revocation;
		encrypted: boolean;
		encoding: DefaultStatusListEncoding;
		encryptedSymmetricKey?: string;
		paymentConditions?: PaymentCondition[];
	};
};
export type StatusList2021SuspensionNonMigrated = {
	StatusList2021: {
		statusPurpose: typeof DefaultStatusList2021StatusPurposeTypes.suspension;
		encodedList: string;
		validFrom: string;
		validUntil?: string;
	};
	metadata: {
		type: typeof DefaultStatusList2021ResourceTypes.suspension;
		encrypted: boolean;
		encoding: DefaultStatusListEncoding;
		encryptedSymmetricKey?: string;
		paymentConditions?: PaymentCondition[];
	};
};
export interface BitstringStatusListEntry extends CredentialStatusReference {
	id: string;
	type: 'BitstringStatusListEntry';
	statusPurpose: BitstringStatusListPurposeType;
	statusListIndex: string; // must be string representation of integer
	statusListCredential: string; // DID URL of the status list credential
	statusSize?: number | 1; // bits per credential (1, 2, 4, 8)
	statusMessage?: BitstringStatusMessage[]; // status value meanings
	statusReference?: string | string[]; // reference to status meanings
}
export interface BitstringStatusMessage {
	status: string; // hex value prefixed with 0x (e.g., "0x0", "0x1")
	message: string; // human-readable explanation
	[key: string]: any; // additional properties can be added
}

export interface EncodedListMetadata {
	encrypted: boolean;
	encoding: DefaultStatusListEncoding;
	length: number;
	statusSize?: number; // bits per credential (1, 2, 4, 8)
	statusMessages?: BitstringStatusMessage[]; // status value meanings
	statusListHash?: string;
	symmetricLength?: number; // length of symmetric encryption ciphertext in bytes
	paymentConditions?: PaymentCondition[];
}
export type BitstringVerifiableCredential = W3CVerifiableCredential & {
	credentialStatus: BitstringStatusListEntry;
};
export type BitstringStatusListCredential = VerifiableCredential & {
	credentialSubject: {
		type: string;
		statusPurpose: BitstringStatusListPurposeType;
		encodedList: EncodedList;
		ttl?: number; // time to live in milliseconds
	};
};
export interface BitstringStatusList {
	bitstringStatusListCredential: BitstringStatusListCredential;
	metadata: EncodedListMetadata;
}
export type AccessControlConditionType = (typeof AccessControlConditionTypes)[keyof typeof AccessControlConditionTypes];
export type AccessControlConditionReturnValueComparator =
	(typeof AccessControlConditionReturnValueComparators)[keyof typeof AccessControlConditionReturnValueComparators];
export type PaymentCondition = {
	feePaymentAddress: string;
	feePaymentAmount: string;
	intervalInSeconds: number;
	blockHeight?: string;
	type: Extract<AccessControlConditionType, 'timelockPayment'>;
};
export type DkgOptions = {
	chain?: Extract<LitCompatibleCosmosChain, 'cheqdTestnet' | 'cheqdMainnet'>;
	network?: LitNetwork;
};
export type CreateStatusList2021Result = {
	created: boolean;
	error?: Error;
	resource: StatusList2021Revocation | StatusList2021Suspension;
	resourceMetadata: LinkedResourceMetadataResolutionResult;
	encrypted?: boolean;
	symmetricKey?: string;
};
export type CreateStatusListResult = {
	created: boolean;
	error?: Error;
	resource: BitstringStatusList;
	resourceMetadata: LinkedResourceMetadataResolutionResult;
	encrypted?: boolean;
	symmetricKey?: string;
};
export type TransactionResult = {
	successful: boolean;
	transactionHash?: string;
	events?: DeliverTxResponse['events'];
	rawLog?: string;
	txResponse?: DeliverTxResponse;
	error?: IError;
};
export type ObservationResult = {
	subscribed: boolean;
	meetsCondition: boolean;
	transactionHash?: string;
	events?: DeliverTxResponse['events'];
	rawLog?: string;
	txResponse?: ShallowTypedTxTxResponses;
	error?: IError;
};

export type MintCapacityCreditResult = {
	minted: boolean;
	error?: IError;
} & Partial<MintCapacityCreditsResult>;

export type DelegateCapacityCreditResult = {
	delegated: boolean;
	error?: IError;
} & Partial<CreateCapacityDelegationAuthSignatureResult>;

export const AccessControlConditionTypes = {
	timelockPayment: 'timelockPayment',
	memoNonce: 'memoNonce',
	balance: 'balance',
} as const;
export const AccessControlConditionReturnValueComparators = {
	lessThan: '<',
	greaterThan: '>',
	equalTo: '=',
	lessThanOrEqualTo: '<=',
	greaterThanOrEqualTo: '>=',
} as const;

export const RemoteListPattern =
	/^(https:\/\/)?[a-z0-9_-]+(\.[a-z0-9_-]+)*\.[a-z]{2,}\/1\.0\/identifiers\/did:cheqd:[a-z]+:[a-zA-Z0-9-]+\?((resourceName=[^&]*)&(resourceType=[^&]*)|((resourceType=[^&]*)&(resourceName=[^&]*)))$/;

export const CreateIdentifierMethodName = 'cheqdCreateIdentifier';
export const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier';
export const DeactivateIdentifierMethodName = 'cheqdDeactivateIdentifier';
export const CreateResourceMethodName = 'cheqdCreateLinkedResource';
export const CreateStatusList2021MethodName = 'cheqdCreateStatusList2021';
export const BroadcastStatusList2021MethodName = 'cheqdBroadcastStatusList2021';
export const GenerateDidDocMethodName = 'cheqdGenerateDidDoc';
export const GenerateDidDocWithLinkedResourceMethodName = 'cheqdGenerateDidDocWithLinkedResource';
export const GenerateKeyPairMethodName = 'cheqdGenerateIdentityKeys';
export const GenerateVersionIdMethodName = 'cheqdGenerateVersionId';
export const GenerateStatusList2021MethodName = 'cheqdGenerateStatusList2021';
export const IssueRevocableCredentialWithStatusList2021MethodName = 'cheqdIssueRevocableCredentialWithStatusList2021';
export const IssueSuspendableCredentialWithStatusList2021MethodName =
	'cheqdIssueSuspendableCredentialWithStatusList2021';

export const CreateStatusListMethodName = 'cheqdCreateStatusList';
export const BroadcastStatusListMethodName = 'cheqdBroadcastStatusList';
export const GenerateStatusListMethodName = 'cheqdGenerateStatusList';
export const VerifyStatusListCredentialMethodName = 'cheqdVerifyStatusListCredential';
export const IssueCredentialWithStatusListMethodName = 'cheqdIssueCredentialWithStatusList';
export const VerifyCredentialWithStatusListMethodName = 'cheqdVerifyCredentialWithStatusList';
export const UpdateCredentialWithStatusListMethodName = 'cheqdUpdateCredentialWithStatusList';
export const BulkUpdateCredentialsWithStatusListMethodName = 'cheqdBulkUpdateCredentialsWithStatusList';
export const VerifyPresentationWithStatusListMethodName = 'cheqdVerifyPresentationWithStatusList';
// END: TODO, start Remove or update with status list 2021
export const VerifyCredentialMethodName = 'cheqdVerifyCredential';
export const VerifyPresentationMethodName = 'cheqdVerifyPresentation';
export const CheckCredentialStatusMethodName = 'cheqdCheckCredentialStatus';
export const RevokeCredentialMethodName = 'cheqdRevokeCredential';
export const RevokeCredentialsMethodName = 'cheqdRevokeCredentials';
export const SuspendCredentialMethodName = 'cheqdSuspendCredential';
export const SuspendCredentialsMethodName = 'cheqdSuspendCredentials';
export const UnsuspendCredentialMethodName = 'cheqdUnsuspendCredential';
export const UnsuspendCredentialsMethodName = 'cheqdUnsuspendCredentials';
// END: Remove or update with status list 2021
export const TransactSendTokensMethodName = 'cheqdTransactSendTokens';
export const ObservePaymentConditionMethodName = 'cheqdObservePaymentCondition';
export const MintCapacityCreditMethodName = 'cheqdMintCapacityCredit';
export const DelegateCapacityCreditMethodName = 'cheqdDelegateCapacityCredit';

export const DidPrefix = 'did';
export const CheqdDidMethod = 'cheqd';

export interface ICheqdCreateIdentifierArgs {
	kms: string;
	alias: string;
	document: DIDDocument;
	keys?: TImportableEd25519Key[];
	versionId?: string;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdUpdateIdentifierArgs {
	kms: string;
	document: DIDDocument;
	keys?: TImportableEd25519Key[] | TPublicKeyEd25519[];
	versionId?: string;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdDeactivateIdentifierArgs {
	kms: string;
	document: DIDDocument;
	keys?: TImportableEd25519Key[] | TPublicKeyEd25519[];
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdCreateLinkedResourceArgs {
	kms: string;
	payload: ResourcePayload;
	network: CheqdNetwork;
	file?: string;
	signInputs?: ISignInputs[] | TPublicKeyEd25519[];
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdCreateStatusList2021Args {
	kms: string;
	issuerDid: string;
	statusListName: string;
	statusPurpose: DefaultStatusList2021StatusPurposeType;
	encrypted: boolean;
	paymentConditions?: PaymentCondition[];
	dkgOptions?: DkgOptions;
	resourceVersion?: ResourcePayload['version'];
	alsoKnownAs?: ResourcePayload['alsoKnownAs'];
	statusListLength?: number;
	statusListEncoding?: DefaultStatusListEncoding;
	validUntil?: string;
	returnSymmetricKey?: boolean;
}

export interface ICheqdCreateUnencryptedStatusList2021Args {
	kms: string;
	payload: StatusList2021ResourcePayload;
	network: CheqdNetwork;
	file?: string;
	signInputs?: ISignInputs[];
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdBroadcastStatusListArgs {
	kms: string;
	payload: StatusList2021ResourcePayload | BitstringStatusListResourcePayload;
	network: CheqdNetwork;
	file?: string;
	signInputs?: ISignInputs[];
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdCreateBitstringStatusListArgs {
	kms: string;
	issuerDid: string;
	statusListName: string;
	statusPurpose: BitstringStatusListPurposeType;
	statusSize?: number; // bits per credential
	statusMessages?: BitstringStatusMessage[];
	ttl?: number; // time to live in milliseconds
	encrypted: boolean;
	paymentConditions?: PaymentCondition[];
	dkgOptions?: DkgOptions;
	resourceVersion?: ResourcePayload['version'];
	alsoKnownAs?: ResourcePayload['alsoKnownAs'];
	statusListLength?: number;
	statusListEncoding?: DefaultStatusListEncoding;
	validUntil?: string;
	returnSymmetricKey?: boolean;
}

export interface ICheqdGenerateDidDocArgs {
	verificationMethod: VerificationMethods;
	methodSpecificIdAlgo: MethodSpecificIdAlgo;
	network: CheqdNetwork;
}

export interface ICheqdGenerateDidDocWithLinkedResourceArgs extends ICheqdGenerateDidDocArgs {
	[key: string]: any;
}

export interface ICheqdGenerateKeyPairArgs {
	[key: string]: any;
}

export interface ICheqdGenerateVersionIdArgs {
	[key: string]: any;
}

export interface ICheqdGenerateStatusList2021Args {
	length?: number;
	buffer?: Uint8Array;
	bitstringEncoding?: DefaultStatusListEncoding;
}

export interface ICheqdGenerateStatusListArgs {
	length?: number; // Number of entries
	statusSize?: number; // Bits per entry
	buffer?: Buffer;
	bitstringEncoding?: DefaultStatusListEncoding;
}

export interface ICheqdVerifyStatusListCredentialArgs {
	credential: BitstringStatusListCredential;
	verificationArgs?: IVerifyCredentialArgs;
}
export interface StatusOptions {
	statusPurpose: BitstringStatusListPurposeType;
	statusListName: string;
	statusListIndex?: number;
	statusListVersion?: string;
	statusListRangeStart?: number;
	statusListRangeEnd?: number;
	indexNotIn?: number[];
}
export interface ICheqdIssueCredentialWithStatusListArgs {
	issuanceOptions: ICreateVerifiableCredentialArgs;
	statusOptions: StatusOptions;
}
export interface ICheqdIssueRevocableCredentialWithStatusList2021Args {
	issuanceOptions: ICreateVerifiableCredentialArgs;
	statusOptions: {
		statusPurpose: 'revocation';
		statusListName: string;
		statusListIndex?: number;
		statusListVersion?: string;
		statusListRangeStart?: number;
		statusListRangeEnd?: number;
		indexNotIn?: number[];
	};
}

export interface ICheqdIssueSuspendableCredentialWithStatusList2021Args {
	issuanceOptions: ICreateVerifiableCredentialArgs;
	statusOptions: {
		statusPurpose: 'suspension';
		statusListName: string;
		statusListIndex?: number;
		statusListVersion?: string;
		statusListRangeStart?: number;
		statusListRangeEnd?: number;
		indexNotIn?: number[];
	};
}

export interface ICheqdVerifyCredentialWithStatusListArgs {
	credential: W3CVerifiableCredential;
	verificationArgs?: IVerifyCredentialArgs;
	fetchList?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
}
export interface ICheqdVerifyCredentialWithBitstringArgs {
	credential: BitstringVerifiableCredential;
	verificationArgs?: IVerifyCredentialArgs;
	fetchList?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
}

export interface ICheqdVerifyPresentationWithStatusListArgs {
	presentation: VerifiablePresentation;
	verificationArgs?: IVerifyPresentationArgs;
	fetchList?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
}

export interface ICheqdCheckCredentialStatusWithStatusListArgs {
	credential?: W3CVerifiableCredential;
	statusOptions?: ICheqdCheckCredentialStatusOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
}

export interface ICheqdUpdateCredentialWithStatusListArgs {
	credential?: W3CVerifiableCredential;
	newStatus: BitstringStatusValue; // 0=valid, 1=revoked, 2=suspended, 3=unknown
	updateOptions?: ICheqdCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}
export interface ICheqdBulkUpdateCredentialWithStatusListArgs {
	credentials?: W3CVerifiableCredential[];
	newStatus: BitstringStatusValue; // 0=valid, 1=revoked, 2=suspended, 3=unknown
	updateOptions?: ICheqdBulkCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdRevokeCredentialWithStatusListArgs {
	credential?: W3CVerifiableCredential;
	revocationOptions?: ICheqdCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
}

export interface ICheqdRevokeBulkCredentialsWithStatusListArgs {
	credentials?: W3CVerifiableCredential[];
	revocationOptions?: ICheqdBulkCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdSuspendCredentialWithStatusListArgs {
	credential?: W3CVerifiableCredential;
	suspensionOptions?: ICheqdCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdSuspendBulkCredentialsWithStatusListArgs {
	credentials?: W3CVerifiableCredential[];
	suspensionOptions?: ICheqdBulkCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdUnsuspendCredentialWithStatusListArgs {
	credential?: W3CVerifiableCredential;
	unsuspensionOptions?: ICheqdCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdUnsuspendBulkCredentialsWithStatusListArgs {
	credentials?: W3CVerifiableCredential[];
	unsuspensionOptions?: ICheqdBulkCredentialStatusUpdateOptions;
	verificationOptions?: IVerifyCredentialArgs;
	fetchList?: boolean;
	publish?: boolean;
	publishEncrypted?: boolean;
	symmetricKey?: string;
	paymentConditions?: PaymentCondition[];
	writeToFile?: boolean;
	returnUpdatedStatusList?: boolean;
	returnSymmetricKey?: boolean;
	returnStatusListMetadata?: boolean;
	dkgOptions?: DkgOptions;
	options?: ICheqdStatusListOptions;
	fee?: DidStdFee | 'auto' | number;
}

export interface ICheqdTransactSendTokensArgs {
	recipientAddress: string;
	amount: Coin;
	network: CheqdNetwork;
	memo?: string;
	txBytes?: Uint8Array;
	returnTxResponse?: boolean;
}

export interface ICheqdObservePaymentConditionArgs {
	recipientAddress?: string;
	amount?: Coin;
	intervalInSeconds?: number;
	blockHeight?: string;
	comparator?: Extract<AccessControlConditionReturnValueComparator, '<' | '<='>;
	network?: CheqdNetwork;
	unifiedAccessControlCondition?: Required<CosmosAccessControlCondition>;
	returnTxResponse?: boolean;
}

export interface ICheqdMintCapacityCreditArgs {
	network: CheqdNetwork;
	effectiveDays: number;
	requestsPerDay?: number;
	requestsPerSecond?: number;
	requestsPerKilosecond?: number;
}

export interface ICheqdDelegateCapacityCreditArgs {
	network: CheqdNetwork;
	capacityTokenId: string;
	delegateeAddresses: string[];
	usesPermitted: number;
	expiration?: string;
	statement?: string;
}

export interface ICheqdStatusListOptions {
	statusListFile?: string;
	statusListInlineBitstring?: string;
	fee?: DidStdFee | 'auto' | number;
	signInputs?: ISignInputs[];

	[key: string]: any;
}

export interface ICheqdCredentialStatusUpdateOptions {
	issuerDid: string;
	statusListName: string;
	statusListIndex: number;
	statusListVersion?: string;
}

export interface ICheqdBulkCredentialStatusUpdateOptions {
	issuerDid: string;
	statusListName: string;
	statusListIndices: number[];
	statusListVersion?: string;
}

export enum BitstringStatusValue {
	VALID = 0, // 0x0 - valid
	REVOKED = 1, // 0x1 - revoked
	SUSPENDED = 2, // 0x2 - suspended
	UNKNOWN = 3, // 0x3 - unknown
}

export interface ICheqdCheckCredentialStatusOptions {
	issuerDid: string;
	statusListName: string;
	statusListIndex: number;
	statusPurpose: DefaultStatusList2021StatusPurposeType | BitstringStatusListPurposeType;
	statusListVersion?: string;
}

export interface ICheqd extends IPluginMethodMap {
	[CreateIdentifierMethodName]: (
		args: ICheqdCreateIdentifierArgs,
		context: IContext
	) => Promise<Omit<IIdentifier, 'provider'>>;
	[UpdateIdentifierMethodName]: (
		args: ICheqdUpdateIdentifierArgs,
		context: IContext
	) => Promise<Omit<IIdentifier, 'provider'>>;
	[DeactivateIdentifierMethodName]: (args: ICheqdDeactivateIdentifierArgs, context: IContext) => Promise<boolean>;
	[CreateResourceMethodName]: (args: ICheqdCreateLinkedResourceArgs, context: IContext) => Promise<boolean>;
	[CreateStatusList2021MethodName]: (
		args: ICheqdCreateStatusList2021Args,
		context: IContext
	) => Promise<CreateStatusList2021Result>;
	[BroadcastStatusList2021MethodName]: (args: ICheqdBroadcastStatusListArgs, context: IContext) => Promise<boolean>;
	[GenerateDidDocMethodName]: (args: ICheqdGenerateDidDocArgs, context: IContext) => Promise<TExportedDIDDocWithKeys>;
	[GenerateDidDocWithLinkedResourceMethodName]: (
		args: ICheqdGenerateDidDocWithLinkedResourceArgs,
		context: IContext
	) => Promise<TExportedDIDDocWithLinkedResourceWithKeys>;
	[GenerateKeyPairMethodName]: (args: ICheqdGenerateKeyPairArgs, context: IContext) => Promise<TImportableEd25519Key>;
	[GenerateVersionIdMethodName]: (args: ICheqdGenerateVersionIdArgs, context: IContext) => Promise<string>;
	[CreateStatusListMethodName]: (
		args: ICheqdCreateBitstringStatusListArgs,
		context: IContext
	) => Promise<CreateStatusListResult>;
	[BroadcastStatusListMethodName]: (args: ICheqdBroadcastStatusListArgs, context: IContext) => Promise<boolean>;
	[GenerateStatusListMethodName]: (args: ICheqdGenerateStatusListArgs, context: IContext) => Promise<string>;
	[VerifyStatusListCredentialMethodName]: (
		args: ICheqdVerifyStatusListCredentialArgs,
		context: IContext
	) => Promise<VerificationResult>;
	[IssueCredentialWithStatusListMethodName]: (
		args: ICheqdIssueCredentialWithStatusListArgs,
		context: IContext
	) => Promise<BitstringVerifiableCredential>;
	[GenerateStatusList2021MethodName]: (args: ICheqdGenerateStatusList2021Args, context: IContext) => Promise<string>;
	[IssueRevocableCredentialWithStatusList2021MethodName]: (
		args: ICheqdIssueRevocableCredentialWithStatusList2021Args,
		context: IContext
	) => Promise<VerifiableCredential>;
	[IssueSuspendableCredentialWithStatusList2021MethodName]: (
		args: ICheqdIssueSuspendableCredentialWithStatusList2021Args,
		context: IContext
	) => Promise<VerifiableCredential>;
	[VerifyCredentialMethodName]: (
		args: ICheqdVerifyCredentialWithStatusListArgs,
		context: IContext
	) => Promise<VerificationResult>;
	[VerifyCredentialWithStatusListMethodName]: (
		args: ICheqdVerifyCredentialWithBitstringArgs,
		context: IContext
	) => Promise<VerificationResult>;
	[VerifyPresentationMethodName]: (
		args: ICheqdVerifyPresentationWithStatusListArgs,
		context: IContext
	) => Promise<VerificationResult>;
	[CheckCredentialStatusMethodName]: (
		args: ICheqdCheckCredentialStatusWithStatusListArgs,
		context: IContext
	) => Promise<StatusCheckResult>;
	[VerifyPresentationWithStatusListMethodName]: (
		args: ICheqdVerifyPresentationWithStatusListArgs,
		context: IContext
	) => Promise<BitstringVerificationResult>;
	[UpdateCredentialWithStatusListMethodName]: (
		args: ICheqdUpdateCredentialWithStatusListArgs,
		context: IContext
	) => Promise<BitstringUpdateResult>;
	[BulkUpdateCredentialsWithStatusListMethodName]: (
		args: ICheqdBulkUpdateCredentialWithStatusListArgs,
		context: IContext
	) => Promise<BulkBitstringUpdateResult>;
	[RevokeCredentialMethodName]: (
		args: ICheqdRevokeCredentialWithStatusListArgs,
		context: IContext
	) => Promise<RevocationResult>;
	[RevokeCredentialsMethodName]: (
		args: ICheqdRevokeBulkCredentialsWithStatusListArgs,
		context: IContext
	) => Promise<BulkRevocationResult>;
	[SuspendCredentialMethodName]: (
		args: ICheqdSuspendCredentialWithStatusListArgs,
		context: IContext
	) => Promise<SuspensionResult>;
	[SuspendCredentialsMethodName]: (
		args: ICheqdSuspendBulkCredentialsWithStatusListArgs,
		context: IContext
	) => Promise<BulkSuspensionResult>;
	[UnsuspendCredentialMethodName]: (
		args: ICheqdUnsuspendCredentialWithStatusListArgs,
		context: IContext
	) => Promise<UnsuspensionResult>;
	[UnsuspendCredentialsMethodName]: (
		args: ICheqdUnsuspendBulkCredentialsWithStatusListArgs,
		context: IContext
	) => Promise<BulkUnsuspensionResult>;
	[TransactSendTokensMethodName]: (
		args: ICheqdTransactSendTokensArgs,
		context: IContext
	) => Promise<TransactionResult>;
	[ObservePaymentConditionMethodName]: (
		args: ICheqdObservePaymentConditionArgs,
		context: IContext
	) => Promise<ObservationResult>;
	[MintCapacityCreditMethodName]: (
		args: ICheqdMintCapacityCreditArgs,
		context: IContext
	) => Promise<MintCapacityCreditResult>;
	[DelegateCapacityCreditMethodName]: (
		args: ICheqdDelegateCapacityCreditArgs,
		context: IContext
	) => Promise<DelegateCapacityCreditResult>;
}

export class Cheqd implements IAgentPlugin {
	readonly methods?: ICheqd;
	readonly schema?: IAgentPluginSchema = {
		components: {
			schemas: {},
			methods: {
				cheqdCreateIdentifier: {
					description: 'Create a new identifier',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdCreateIdentifierArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdUpdateIdentifier: {
					description: 'Update an identifier',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdUpdateIdentifierArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdDeactivateIdentifier: {
					description: 'Deactivate an identifier',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdDeactivateIdentifierArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdCreateLinkedResource: {
					description: 'Create a new resource',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdCreateLinkedResource object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'boolean',
					},
				},
				cheqdCreateStatusList2021: {
					description: 'Create a new Status List 2021',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdCreateStatusList2021Args object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdCreateStatusList: {
					description: 'Create a new Bitstring Status List',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdCreateBitstringStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdBroadcastStatusList2021: {
					description: 'Broadcast a Status List 2021 to cheqd ledger',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdBroadcastStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdBroadcastStatusList: {
					description: 'Broadcast a Bitstring Status List to cheqd ledger',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdBroadcastStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdGenerateDidDoc: {
					description: 'Generate a new DID document to use with `createIdentifier`',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdGenerateDidDocArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdGenerateDidDocWithLinkedResource: {
					description: 'Generate a new DID document to use with `createIdentifier` and / or `createResource`',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdGenerateDidDocWithLinkedResourceArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdGenerateIdentityKeys: {
					description: 'Generate a new key pair in hex to use with `createIdentifier`',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdGenerateIdentityKeysArgs object as any for extensibility',
							},
						},
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdGenerateVersionId: {
					description: 'Generate a random uuid',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdGenerateVersionIdArgs object as any for extensibility',
							},
						},
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdGenerateStatusList2021: {
					description: 'Generate a new Status List 2021',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdGenerateStatusList2021Args object as any for extensibility',
							},
						},
					},
					returnType: {
						type: 'string',
					},
				},
				cheqdGenerateStatusList: {
					description: 'Generate a new Bitstring Status List',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdGenerateStatusListArgs object as any for extensibility',
							},
						},
					},
					returnType: {
						type: 'string',
					},
				},
				cheqdIssueCredentialWithStatusList: {
					description:
						'Issue a revocable or suspendable credential with a Bitstring Status List as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdIssueCredentialWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdIssueRevocableCredentialWithStatusList2021: {
					description: 'Issue a revocable credential with a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdIssueRevocableCredentialWithStatusList2021Args object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdIssueSuspendableCredentialWithStatusList2021: {
					description: 'Issue a suspendable credential with a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdIssueSuspendableCredentialWithStatusList2021Args object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdVerifyCredential: {
					description:
						'Verify a credential, enhanced by revocation / suspension check with a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdVerifyCredentialWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdVerifyCredentialWithStatusList: {
					description:
						'Verify a credential, enhanced by revocation / suspension check with a Bitstring Status List as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdVerifyCredentialWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdVerifyPresentation: {
					description:
						'Verify a presentation, enhanced by revocation / suspension check with a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdVerifyPresentationWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdCheckCredentialStatus: {
					description:
						'Check the revocation / suspension status of a credential with a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdCheckCredentialStatusWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdRevokeCredential: {
					description: 'Revoke a credential against a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdRevokeCredentialWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdRevokeCredentials: {
					description: 'Revoke multiple credentials against a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdRevokeBulkCredentialsWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'array',
					},
				},
				cheqdSuspendCredential: {
					description: 'Suspend a credential against a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdSuspendCredentialWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdSuspendCredentials: {
					description:
						'Suspend multiple credentials against a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdSuspendBulkCredentialsWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'array',
					},
				},
				cheqdUnsuspendCredential: {
					description: 'Unsuspend a credential against a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'cheqdUnsuspendCredentialWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdUnsuspendCredentials: {
					description:
						'Unsuspend multiple credentials against a Status List 2021 as credential status registry',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description:
									'A cheqdUnsuspendBulkCredentialsWithStatusListArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'array',
					},
				},
				cheqdTransactSendTokens: {
					description: 'Send tokens from one account to another',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'A cheqdTransactSendTokensArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
				cheqdObservePaymentCondition: {
					description: 'Observe payment conditions for a given set of payment conditions',
					arguments: {
						type: 'object',
						properties: {
							args: {
								type: 'object',
								description: 'cheqdObservePaymentConditionArgs object as any for extensibility',
							},
						},
						required: ['args'],
					},
					returnType: {
						type: 'object',
					},
				},
			},
		},
	};
	private readonly supportedDidProviders: CheqdDIDProvider[];
	private didProvider: CheqdDIDProvider;
	private providerId: string;
	// Deprecate below constants in future versions
	static readonly defaultStatusList2021Length: number = 16 * 1024 * 8; // 16KB in bits or 131072 bits / entries
	static readonly defaultContextV1 = 'https://www.w3.org/2018/credentials/v1';
	static readonly statusList2021Context = 'https://w3id.org/vc-status-list-2021/v1';
	// END: Deprecate
	static readonly DefaultBitstringContexts = {
		v2: 'https://www.w3.org/ns/credentials/v2',
		statusList: 'https://www.w3.org/ns/credentials/status/v1',
	};
	// Default bitstring status list size in bits
	static readonly DefaultBitstringStatusSize: number = 2; // 2 bits per credential (0, 1, 2, 3)
	// Minimum bitstring length for compliance
	static readonly DefaultBitstringLength: number = 16 * 1024 * 8; // 16KB in bits or 131072 bits (spec minimum)

	constructor(args: { providers: CheqdDIDProvider[] }) {
		if (typeof args.providers !== 'object') {
			throw new Error('[did-provider-cheqd]: at least one did provider is required');
		}

		this.supportedDidProviders = args.providers;
		this.didProvider = args.providers[0];
		this.providerId = Cheqd.generateProviderId(this.didProvider.network);

		this.methods = {
			[CreateIdentifierMethodName]: this.CreateIdentifier.bind(this),
			[UpdateIdentifierMethodName]: this.UpdateIdentifier.bind(this),
			[DeactivateIdentifierMethodName]: this.DeactivateIdentifier.bind(this),
			[CreateResourceMethodName]: this.CreateResource.bind(this),
			[CreateStatusList2021MethodName]: this.CreateStatusList2021.bind(this),
			[BroadcastStatusList2021MethodName]: this.BroadcastStatusList2021.bind(this),
			[CreateStatusListMethodName]: this.CreateBitstringStatusList.bind(this),
			[BroadcastStatusListMethodName]: this.BroadcastBitstringStatusList.bind(this),
			[GenerateDidDocMethodName]: this.GenerateDidDoc.bind(this),
			[GenerateDidDocWithLinkedResourceMethodName]: this.GenerateDidDocWithLinkedResource.bind(this),
			[GenerateKeyPairMethodName]: this.GenerateIdentityKeys.bind(this),
			[GenerateVersionIdMethodName]: this.GenerateVersionId.bind(this),
			[GenerateStatusList2021MethodName]: this.GenerateStatusList2021.bind(this),
			[GenerateStatusListMethodName]: this.GenerateBitstringStatusList.bind(this),
			[VerifyStatusListCredentialMethodName]: this.VerifyStatusListCredential.bind(this),
			[IssueCredentialWithStatusListMethodName]: this.IssueCredentialWithBitstringStatusList.bind(this),
			[IssueRevocableCredentialWithStatusList2021MethodName]:
				this.IssueRevocableCredentialWithStatusList2021.bind(this),
			[IssueSuspendableCredentialWithStatusList2021MethodName]:
				this.IssueSuspendableCredentialWithStatusList2021.bind(this),
			[VerifyCredentialMethodName]: this.VerifyCredentialWithStatusList2021.bind(this),
			[VerifyCredentialWithStatusListMethodName]: this.VerifyCredentialWithBitstringStatusList.bind(this),
			[VerifyPresentationMethodName]: this.VerifyPresentationWithStatusList2021.bind(this),
			[CheckCredentialStatusMethodName]: this.CheckCredentialStatusWithStatusList2021.bind(this),
			[VerifyPresentationWithStatusListMethodName]: this.VerifyPresentationWithBitstringStatusList.bind(this),
			[UpdateCredentialWithStatusListMethodName]: this.UpdateCredentialWithStatusList.bind(this),
			[BulkUpdateCredentialsWithStatusListMethodName]: this.BulkUpdateCredentialsWithStatusList.bind(this),
			[RevokeCredentialMethodName]: this.RevokeCredentialWithStatusList2021.bind(this),
			[RevokeCredentialsMethodName]: this.RevokeBulkCredentialsWithStatusList2021.bind(this),
			[SuspendCredentialMethodName]: this.SuspendCredentialWithStatusList2021.bind(this),
			[SuspendCredentialsMethodName]: this.SuspendBulkCredentialsWithStatusList2021.bind(this),
			[UnsuspendCredentialMethodName]: this.UnsuspendCredentialWithStatusList2021.bind(this),
			[UnsuspendCredentialsMethodName]: this.UnsuspendBulkCredentialsWithStatusList2021.bind(this),
			[TransactSendTokensMethodName]: this.TransactSendTokens.bind(this),
			[ObservePaymentConditionMethodName]: this.ObservePaymentCondition.bind(this),
			[MintCapacityCreditMethodName]: this.MintCapacityCredit.bind(this),
			[DelegateCapacityCreditMethodName]: this.DelegateCapacityCredit.bind(this),
		};
	}

	private async CreateIdentifier(
		args: ICheqdCreateIdentifierArgs,
		context: IContext
	): Promise<Omit<IIdentifier, 'provider'>> {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.alias !== 'string') {
			throw new Error('[did-provider-cheqd]: alias is required');
		}

		if (typeof args.document !== 'object') {
			throw new Error('[did-provider-cheqd]: document object is required');
		}

		const provider = await Cheqd.getProviderFromDidUrl(args.document.id, this.supportedDidProviders);

		this.didProvider = provider;
		this.providerId = Cheqd.generateProviderId(this.didProvider.network);

		return await context.agent.didManagerCreate({
			kms: args.kms,
			alias: args.alias,
			provider: this.providerId,
			options: {
				document: args.document,
				keys: args.keys,
				versionId: args?.versionId,
				fee: args?.fee,
			},
		});
	}

	private async UpdateIdentifier(
		args: ICheqdUpdateIdentifierArgs,
		context: IContext
	): Promise<Omit<IIdentifier, 'provider'>> {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.document !== 'object') {
			throw new Error('[did-provider-cheqd]: document object is required');
		}

		const provider = await Cheqd.getProviderFromDidUrl(args.document.id, this.supportedDidProviders);

		this.didProvider = provider;
		this.providerId = Cheqd.generateProviderId(this.didProvider.network);

		return await context.agent.didManagerUpdate({
			did: args.document.id,
			document: args.document,
			options: {
				kms: args.kms,
				keys: args.keys,
				versionId: args?.versionId,
				fee: args?.fee,
			},
		});
	}

	private async DeactivateIdentifier(args: ICheqdDeactivateIdentifierArgs, context: IContext) {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.document !== 'object') {
			throw new Error('[did-provider-cheqd]: document object is required');
		}

		const provider = await Cheqd.getProviderFromDidUrl(args.document.id, this.supportedDidProviders);

		this.didProvider = provider;
		this.providerId = Cheqd.generateProviderId(this.didProvider.network);

		return await this.didProvider.deactivateIdentifier(
			{
				did: args.document.id,
				document: args.document,
				options: {
					keys: args.keys,
					fee: args?.fee,
				},
			},
			context
		);
	}

	private async CreateResource(args: ICheqdCreateLinkedResourceArgs, context: IContext) {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.payload !== 'object') {
			throw new Error('[did-provider-cheqd]: payload object is required');
		}

		if (typeof args.network !== 'string') {
			throw new Error('[did-provider-cheqd]: network is required');
		}

		if (args?.file) {
			args.payload.data = await Cheqd.getFile(args.file);
		}

		if (typeof args?.payload?.data === 'string') {
			args.payload.data = fromString(args.payload.data, 'base64');
		}

		this.providerId = Cheqd.generateProviderId(args.network);
		this.didProvider = await Cheqd.getProviderFromNetwork(args.network, this.supportedDidProviders);

		return await this.didProvider.createResource(
			{
				options: {
					kms: args.kms,
					payload: args.payload,
					signInputs: args.signInputs,
					fee: args?.fee,
				},
			},
			context
		);
	}

	private async CreateStatusList2021(args: ICheqdCreateStatusList2021Args, context: IContext) {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.issuerDid !== 'string' || !args.issuerDid) {
			throw new Error('[did-provider-cheqd]: issuerDid is required');
		}

		if (typeof args.statusListName !== 'string' || !args.statusListName) {
			throw new Error('[did-provider-cheqd]: statusListName is required');
		}

		if (typeof args.statusPurpose !== 'string' || !args.statusPurpose) {
			throw new Error('[did-provider-cheqd]: statusPurpose is required');
		}

		if (typeof args.encrypted === 'undefined') {
			throw new Error('[did-provider-cheqd]: encrypted is required');
		}

		// validate statusPurpose
		if (!Object.values(DefaultStatusList2021StatusPurposeTypes).includes(args.statusPurpose)) {
			throw new Error(
				`[did-provider-cheqd]: statusPurpose must be one of ${Object.values(
					DefaultStatusList2021StatusPurposeTypes
				).join(', ')}`
			);
		}

		// validate statusListLength
		if (args?.statusListLength) {
			if (typeof args.statusListLength !== 'number') {
				throw new Error('[did-provider-cheqd]: statusListLength must be number');
			}

			if (args.statusListLength < Cheqd.defaultStatusList2021Length) {
				throw new Error(
					`[did-provider-cheqd]: statusListLength must be greater than or equal to ${Cheqd.defaultStatusList2021Length} number of entries`
				);
			}
		}

		// validate statusListEncoding
		if (args?.statusListEncoding) {
			if (typeof args.statusListEncoding !== 'string') {
				throw new Error('[did-provider-cheqd]: statusListEncoding must be string');
			}

			if (!Object.values(DefaultStatusListEncodings).includes(args.statusListEncoding)) {
				throw new Error(
					`[did-provider-cheqd]: statusListEncoding must be one of ${Object.values(
						DefaultStatusListEncodings
					).join(', ')}`
				);
			}
		}

		// validate validUntil
		if (args?.validUntil) {
			if (typeof args.validUntil !== 'string') {
				throw new Error('[did-provider-cheqd]: validUntil must be string');
			}

			if (new Date() <= new Date(args.validUntil)) {
				throw new Error('[did-provider-cheqd]: validUntil must be greater than current date');
			}
		}

		// validate args in pairs - case: encrypted
		if (args.encrypted) {
			// validate paymentConditions
			if (
				!args?.paymentConditions ||
				!args?.paymentConditions?.length ||
				!Array.isArray(args?.paymentConditions) ||
				args?.paymentConditions.length === 0
			) {
				throw new Error('[did-provider-cheqd]: paymentConditions is required');
			}

			if (
				!args?.paymentConditions?.every(
					(condition) =>
						condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds
				)
			) {
				throw new Error(
					'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
				);
			}

			if (
				!args?.paymentConditions?.every(
					(condition) =>
						typeof condition.feePaymentAddress === 'string' &&
						typeof condition.feePaymentAmount === 'string' &&
						typeof condition.intervalInSeconds === 'number'
				)
			) {
				throw new Error(
					'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
				);
			}

			if (
				!args?.paymentConditions?.every(
					(condition) => condition.type === AccessControlConditionTypes.timelockPayment
				)
			) {
				throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment');
			}
		}

		// get network
		const network = args.issuerDid.split(':')[2];

		// define provider
		const provider = (function (that) {
			// switch on network
			return (
				that.supportedDidProviders.find((provider) => provider.network === network) ||
				(function () {
					throw new Error(`[did-provider-cheqd]: no relevant providers found`);
				})()
			);
		})(this);

		// generate bitstring
		const bitstring = await context.agent[GenerateStatusList2021MethodName]({
			length: args?.statusListLength || Cheqd.defaultStatusList2021Length,
			bitstringEncoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
		});

		// construct data and metadata tuple
		const data = args.encrypted
			? await (async function (that: Cheqd) {
					// encrypt bitstring - case: symmetric
					const { encryptedString: symmetricEncryptionCiphertext, symmetricKey } =
						await LitProtocol.encryptDirect(
							fromString(bitstring, args?.statusListEncoding || DefaultStatusListEncodings.base64url)
						);

					// instantiate dkg-threshold client, in which case lit-protocol is used
					const lit = await provider.instantiateDkgThresholdProtocolClient({});

					// construct access control conditions
					const unifiedAccessControlConditions = await Promise.all(
						args.paymentConditions!.map(async (condition) => {
							switch (condition.type) {
								case AccessControlConditionTypes.timelockPayment:
									return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
										{
											key: '$.tx_responses.*.timestamp',
											comparator: '<=',
											value: `${condition.intervalInSeconds}`,
										},
										condition.feePaymentAmount,
										condition.feePaymentAddress,
										condition?.blockHeight,
										args?.dkgOptions?.chain || that.didProvider.dkgOptions.chain
									);
								default:
									throw new Error(
										`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
									);
							}
						})
					);

					// encrypt bitstring - case: threshold
					const { encryptedString: thresholdEncryptionCiphertext, stringHash } = await lit.encrypt(
						fromString(bitstring, args?.statusListEncoding || DefaultStatusListEncodings.base64url),
						unifiedAccessControlConditions
					);

					// construct encoded list
					const encodedList = `${await blobToHexString(symmetricEncryptionCiphertext)}-${toString(
						thresholdEncryptionCiphertext,
						'hex'
					)}`;

					// return result tuple
					switch (args.statusPurpose) {
						case DefaultStatusList2021StatusPurposeTypes.revocation:
							return [
								{
									StatusList2021: {
										statusPurpose: args.statusPurpose,
										encodedList,
										validFrom: new Date().toISOString(),
										validUntil: args?.validUntil,
									},
									metadata: {
										type: DefaultStatusList2021ResourceTypes.revocation,
										encrypted: true,
										encoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
										statusListHash: stringHash,
										paymentConditions: args.paymentConditions,
									},
								} satisfies StatusList2021Revocation,
								{
									symmetricEncryptionCiphertext: await blobToHexString(symmetricEncryptionCiphertext),
									thresholdEncryptionCiphertext: toString(thresholdEncryptionCiphertext, 'hex'),
									stringHash,
									symmetricKey: toString(symmetricKey, 'hex'),
								},
							] satisfies [StatusList2021Revocation, EncryptionResult];
						case DefaultStatusList2021StatusPurposeTypes.suspension:
							return [
								{
									StatusList2021: {
										statusPurpose: args.statusPurpose,
										encodedList,
										validFrom: new Date().toISOString(),
										validUntil: args?.validUntil,
									},
									metadata: {
										type: DefaultStatusList2021ResourceTypes.suspension,
										encrypted: true,
										encoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
										statusListHash: stringHash,
										paymentConditions: args.paymentConditions,
									},
								} satisfies StatusList2021Suspension,
								{
									symmetricEncryptionCiphertext: await blobToHexString(symmetricEncryptionCiphertext),
									thresholdEncryptionCiphertext: toString(thresholdEncryptionCiphertext, 'hex'),
									stringHash,
									symmetricKey: toString(symmetricKey, 'hex'),
								},
							] satisfies [StatusList2021Suspension, EncryptionResult];
						default:
							throw new Error(`[did-provider-cheqd]: status purpose is not valid ${args.statusPurpose}`);
					}
				})(this)
			: await (async function () {
					switch (args.statusPurpose) {
						case DefaultStatusList2021StatusPurposeTypes.revocation:
							return [
								{
									StatusList2021: {
										statusPurpose: args.statusPurpose,
										encodedList: bitstring,
										validFrom: new Date().toISOString(),
										validUntil: args?.validUntil,
									},
									metadata: {
										type: DefaultStatusList2021ResourceTypes.revocation,
										encrypted: false,
										encoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
									},
								} satisfies StatusList2021Revocation,
								undefined,
							] satisfies [StatusList2021Revocation, undefined];
						case DefaultStatusList2021StatusPurposeTypes.suspension:
							return [
								{
									StatusList2021: {
										statusPurpose: args.statusPurpose,
										encodedList: bitstring,
										validFrom: new Date().toISOString(),
										validUntil: args?.validUntil,
									},
									metadata: {
										type: DefaultStatusList2021ResourceTypes.suspension,
										encrypted: false,
										encoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
									},
								} satisfies StatusList2021Suspension,
								undefined,
							] satisfies [StatusList2021Suspension, undefined];
						default:
							throw new Error('[did-provider-cheqd]: statusPurpose is not valid');
					}
				})();

		// construct payload
		const payload = {
			id: v4(),
			collectionId: args.issuerDid.split(':').reverse()[0],
			name: args.statusListName,
			resourceType: DefaultStatusList2021ResourceTypes[args.statusPurpose],
			version: args?.resourceVersion || new Date().toISOString(),
			alsoKnownAs: args?.alsoKnownAs || [],
			data: fromString(JSON.stringify(data[0]), 'utf-8'),
		} satisfies StatusList2021ResourcePayload;

		// return result
		return {
			created: await context.agent[BroadcastStatusList2021MethodName]({
				kms: args.kms,
				payload,
				network: network as CheqdNetwork,
			}),
			resource: data[0],
			resourceMetadata: await Cheqd.fetchStatusListMetadata({
				credentialStatus: {
					id: `${DefaultResolverUrl}${args.issuerDid}?resourceName=${args.statusListName}&resourceType=${
						DefaultStatusList2021ResourceTypes[args.statusPurpose]
					}`,
					type: 'StatusList2021Entry',
				},
			} as VerifiableCredential),
			encrypted: args.encrypted,
			symmetricKey: args.encrypted && args.returnSymmetricKey ? data[1]?.symmetricKey : undefined,
		} satisfies CreateStatusList2021Result;
	}

	private async BroadcastStatusList2021(args: ICheqdBroadcastStatusListArgs, context: IContext) {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.payload !== 'object') {
			throw new Error('[did-provider-cheqd]: payload object is required');
		}

		if (typeof args.network !== 'string') {
			throw new Error('[did-provider-cheqd]: network is required');
		}

		if (args?.file) {
			args.payload.data = await Cheqd.getFile(args.file);
		}

		if (typeof args?.payload?.data === 'string') {
			args.payload.data = fromString(args.payload.data, 'base64');
		}

		// TODO: validate data as per bitstring

		// validate resource type
		const allowedTypes = [...Object.values(DefaultStatusList2021ResourceTypes), 'BitstringStatusListCredential'];
		if (!Object.values(allowedTypes).includes(args?.payload?.resourceType)) {
			throw new Error(
				`[did-provider-cheqd]: resourceType must be one of ${Object.values(allowedTypes).join(', ')}`
			);
		}

		this.providerId = Cheqd.generateProviderId(args.network);
		this.didProvider = await Cheqd.getProviderFromNetwork(args.network, this.supportedDidProviders);

		return await this.didProvider.createResource(
			{
				options: {
					kms: args.kms,
					payload: args.payload,
					signInputs: args.signInputs,
					fee:
						args?.fee ||
						(await ResourceModule.generateCreateResourceJsonFees(
							(await this.didProvider.getWalletAccounts())[0].address
						)),
				},
			},
			context
		);
	}

	private async CreateBitstringStatusList(args: ICheqdCreateBitstringStatusListArgs, context: IContext) {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}
		if (typeof args.issuerDid !== 'string' || !args.issuerDid) {
			throw new Error('[did-provider-cheqd]: issuerDid is required');
		}
		if (typeof args.statusListName !== 'string' || !args.statusListName) {
			throw new Error('[did-provider-cheqd]: statusListName is required');
		}
		if (!args.statusPurpose) {
			throw new Error('[did-provider-cheqd]: statusPurpose is required');
		}
		if (typeof args.encrypted === 'undefined') {
			throw new Error('[did-provider-cheqd]: encrypted is required');
		}
		// validate statusPurpose
		const statusPurpose = Array.isArray(args.statusPurpose) ? args.statusPurpose[0] : args.statusPurpose;
		if (!Object.values(BitstringStatusPurposeTypes).includes(statusPurpose)) {
			throw new Error(
				`[did-provider-cheqd]: statusPurpose must be in ${Object.values(BitstringStatusPurposeTypes).join(
					', '
				)}`
			);
		}
		// validate statusListLength
		if (args?.statusListLength) {
			if (typeof args.statusListLength !== 'number') {
				throw new Error('[did-provider-cheqd]: statusListLength must be number');
			}
			if (args.statusListLength < Cheqd.DefaultBitstringLength) {
				throw new Error(
					`[did-provider-cheqd]: statusListLength must be greater than or equal to ${Cheqd.DefaultBitstringLength} number of entries`
				);
			}
		}
		// validate statusListEncoding, W3C spec only supports base64url encoding
		if (args?.statusListEncoding) {
			if (typeof args.statusListEncoding !== 'string') {
				throw new Error('[did-provider-cheqd]: statusListEncoding must be string');
			}

			if (args.statusListEncoding !== DefaultStatusListEncodings.base64url) {
				throw new Error(
					`[did-provider-cheqd]: statusListEncoding must be ${DefaultStatusListEncodings.base64url}`
				);
			}
		}
		// validate validUntil
		if (args?.validUntil) {
			if (typeof args.validUntil !== 'string') {
				throw new Error('[did-provider-cheqd]: validUntil must be string');
			}

			if (new Date() <= new Date(args.validUntil)) {
				throw new Error('[did-provider-cheqd]: validUntil must be greater than current date');
			}
		}
		// validate args in pairs - case: encrypted
		if (args.encrypted) {
			// validate paymentConditions
			if (
				!args?.paymentConditions ||
				!args?.paymentConditions?.length ||
				!Array.isArray(args?.paymentConditions) ||
				args?.paymentConditions.length === 0
			) {
				throw new Error('[did-provider-cheqd]: paymentConditions is required');
			}

			if (
				!args?.paymentConditions?.every(
					(condition) =>
						condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds
				)
			) {
				throw new Error(
					'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
				);
			}

			if (
				!args?.paymentConditions?.every(
					(condition) =>
						typeof condition.feePaymentAddress === 'string' &&
						typeof condition.feePaymentAmount === 'string' &&
						typeof condition.intervalInSeconds === 'number'
				)
			) {
				throw new Error(
					'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
				);
			}

			if (
				!args?.paymentConditions?.every(
					(condition) => condition.type === AccessControlConditionTypes.timelockPayment
				)
			) {
				throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment');
			}
		}
		// get network
		const network = args.issuerDid.split(':')[2];
		// define provider
		const provider = (function (that) {
			// switch on network
			return (
				that.supportedDidProviders.find((provider) => provider.network === network) ||
				(function () {
					throw new Error(`[did-provider-cheqd]: no relevant providers found`);
				})()
			);
		})(this);
		// generate bitstring
		const bitstring = await context.agent[GenerateStatusListMethodName]({
			statusSize: args?.statusSize,
			length: args?.statusListLength,
			bitstringEncoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
		});
		// Generate proof without credentialSubject.encodedList property
		const issuanceOptions = {
			credential: {
				'@context': [Cheqd.defaultContextV1], // TODO: use v2 context when v2 credential support enabled
				type: ['VerifiableCredential', BitstringStatusListResourceType],
				issuer: args.issuerDid,
				issuanceDate: new Date().toISOString(),
				expirationDate: args?.validUntil,
				credentialSubject: {
					type: 'BitstringStatusList',
					statusPurpose: args.statusPurpose,
					ttl: args?.ttl,
				},
			},
			proofFormat: 'jwt',
		} as ICreateVerifiableCredentialArgs;
		const issued = await context.agent.createVerifiableCredential(issuanceOptions);
		// construct data and metadata tuple
		const data = args.encrypted
			? await (async function (that: Cheqd) {
					// encrypt bitstring - case: symmetric
					const { encryptedString: symmetricEncryptionCiphertext, symmetricKey } =
						await LitProtocol.encryptDirect(
							fromString(bitstring, args?.statusListEncoding || DefaultStatusListEncodings.base64url)
						);

					// instantiate dkg-threshold client, in which case lit-protocol is used
					const lit = await provider.instantiateDkgThresholdProtocolClient({});

					// construct access control conditions
					const unifiedAccessControlConditions = await Promise.all(
						args.paymentConditions!.map(async (condition) => {
							switch (condition.type) {
								case AccessControlConditionTypes.timelockPayment:
									return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
										{
											key: '$.tx_responses.*.timestamp',
											comparator: '<=',
											value: `${condition.intervalInSeconds}`,
										},
										condition.feePaymentAmount,
										condition.feePaymentAddress,
										condition?.blockHeight,
										args?.dkgOptions?.chain || that.didProvider.dkgOptions.chain
									);
								default:
									throw new Error(
										`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
									);
							}
						})
					);
					// encrypt bitstring - case: threshold
					const { encryptedString: thresholdEncryptionCiphertext, stringHash } = await lit.encrypt(
						fromString(bitstring, args?.statusListEncoding || DefaultStatusListEncodings.base64url),
						unifiedAccessControlConditions
					);
					// construct encoded list
					const { encodedList, symmetricLength } = await encodeWithMetadata(
						symmetricEncryptionCiphertext,
						thresholdEncryptionCiphertext
					);
					issued.credentialSubject = {
						type: 'BitstringStatusList',
						statusPurpose: args.statusPurpose,
						encodedList,
						ttl: args?.ttl,
					};

					// return result tuple
					return [
						{
							bitstringStatusListCredential: issued as BitstringStatusListCredential,
							metadata: {
								encrypted: true,
								encoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
								length: args?.statusListLength || Cheqd.DefaultBitstringLength,
								statusSize: args?.statusSize,
								statusMessages: args?.statusMessages || [],
								statusListHash: stringHash,
								symmetricLength,
								paymentConditions: args.paymentConditions,
							},
						} satisfies BitstringStatusList,
						{
							symmetricEncryptionCiphertext: await blobToHexString(symmetricEncryptionCiphertext),
							thresholdEncryptionCiphertext: toString(thresholdEncryptionCiphertext, 'hex'),
							stringHash,
							symmetricKey: toString(symmetricKey, 'hex'),
						},
					] satisfies [BitstringStatusList, EncryptionResult];
				})(this)
			: await (async function () {
					issued.credentialSubject = {
						type: 'BitstringStatusList',
						statusPurpose: args.statusPurpose,
						encodedList: bitstring,
						ttl: args?.ttl,
					};
					return [
						{
							bitstringStatusListCredential: issued as BitstringStatusListCredential,
							metadata: {
								encrypted: false,
								encoding: args?.statusListEncoding || DefaultStatusListEncodings.base64url,
								length: args?.statusListLength || Cheqd.DefaultBitstringLength,
								statusSize: args?.statusSize,
								statusMessages: args?.statusMessages || [],
							},
						} satisfies BitstringStatusList,
						undefined,
					] satisfies [BitstringStatusList, undefined];
				})();

		// construct payload
		const payload = {
			id: v4(),
			collectionId: args.issuerDid.split(':').reverse()[0],
			name: args.statusListName,
			resourceType: BitstringStatusListResourceType,
			version: args?.resourceVersion || new Date().toISOString(),
			alsoKnownAs: args?.alsoKnownAs || [],
			data: fromString(JSON.stringify(data[0]), 'utf-8'),
		} satisfies BitstringStatusListResourcePayload;

		// return result
		return {
			created: await context.agent[BroadcastStatusListMethodName]({
				kms: args.kms,
				payload,
				network: network as CheqdNetwork,
			}),
			resource: data[0],
			resourceMetadata: await Cheqd.fetchStatusListMetadata({
				credentialStatus: {
					id: `${DefaultResolverUrl}${args.issuerDid}?resourceName=${args.statusListName}&resourceType=${
						BitstringStatusListResourceType
					}`,
				},
			} as VerifiableCredential),
			encrypted: args.encrypted,
			symmetricKey: args.encrypted && args.returnSymmetricKey ? data[1]?.symmetricKey : undefined,
		} satisfies CreateStatusListResult;
	}
	private async BroadcastBitstringStatusList(args: ICheqdBroadcastStatusListArgs, context: IContext) {
		if (typeof args.kms !== 'string') {
			throw new Error('[did-provider-cheqd]: kms is required');
		}

		if (typeof args.payload !== 'object') {
			throw new Error('[did-provider-cheqd]: payload object is required');
		}

		if (typeof args.network !== 'string') {
			throw new Error('[did-provider-cheqd]: network is required');
		}

		if (args?.file) {
			args.payload.data = await Cheqd.getFile(args.file);
		}

		if (typeof args?.payload?.data === 'string') {
			args.payload.data = fromString(args.payload.data, 'base64');
		}
		// Validate that data is present
		if (!args.payload.data) {
			throw new Error('[did-provider-cheqd]: payload.data is required for Bitstring Status List');
		}

		// Validate and parse the Bitstring Status List data
		await this.validateBitstringStatusListPayload(args.payload as BitstringStatusListResourcePayload);

		// Validate against resource type
		if (args?.payload?.resourceType !== BitstringStatusListResourceType) {
			throw new Error(`[did-provider-cheqd]: resourceType must be ${BitstringStatusListResourceType}`);
		}

		this.providerId = Cheqd.generateProviderId(args.network);
		this.didProvider = await Cheqd.getProviderFromNetwork(args.network, this.supportedDidProviders);

		return await this.didProvider.createResource(
			{
				options: {
					kms: args.kms,
					payload: args.payload,
					signInputs: args.signInputs,
					fee:
						args?.fee ||
						(await ResourceModule.generateCreateResourceJsonFees(
							(await this.didProvider.getWalletAccounts())[0].address
						)),
				},
			},
			context
		);
	}
	/**
	 * Validate Bitstring Status List payload structure and content
	 */
	private async validateBitstringStatusListPayload(payload: BitstringStatusListResourcePayload): Promise<void> {
		if (!payload.data) {
			throw new Error('[did-provider-cheqd]: payload.data is required');
		}
		let bitstringData: BitstringStatusList;
		try {
			// Parse the data as BitstringStatusList
			const dataString = typeof payload.data === 'string' ? payload.data : toString(payload.data, 'utf-8');
			bitstringData = JSON.parse(dataString) as BitstringStatusList;
		} catch (error) {
			throw new Error(
				`[did-provider-cheqd]: Invalid BitstringStatusList data format: ${(error as Error).message}`
			);
		}
		const metadata = bitstringData.metadata;
		const bitstringCredential = bitstringData.bitstringStatusListCredential;
		// Validate required properties
		if (!bitstringCredential.credentialSubject.statusPurpose) {
			throw new Error('[did-provider-cheqd]: statusPurpose is required');
		}

		if (!bitstringCredential.credentialSubject.encodedList) {
			throw new Error('[did-provider-cheqd]: encodedList is required');
		}

		if (!bitstringCredential.issuanceDate) {
			throw new Error('[did-provider-cheqd]: issuanceDate is required');
		}
		// Validate status purpose
		const statusPurpose = Array.isArray(bitstringCredential.credentialSubject.statusPurpose)
			? bitstringCredential.credentialSubject.statusPurpose[0]
			: bitstringCredential.credentialSubject.statusPurpose;
		if (!Object.values(BitstringStatusPurposeTypes).includes(statusPurpose)) {
			throw new Error(
				`[did-provider-cheqd]: Invalid statusPurpose. Must be in: ${Object.values(
					BitstringStatusPurposeTypes
				).join(', ')}`
			);
		}
		// Validate encoded list format (should be base64url encoded)
		if (!isValidEncodedBitstring(bitstringCredential.credentialSubject.encodedList)) {
			throw new Error(
				'[did-provider-cheqd]: Invalid encodedList format. Must be base64url encoded GZIP compressed bitstring'
			);
		}
		// Validate dates
		try {
			new Date(bitstringCredential.issuanceDate);
			if (bitstringCredential.expirationDate) {
				const validUntil = new Date(bitstringCredential.expirationDate);
				const validFrom = new Date(bitstringCredential.issuanceDate);
				if (validUntil <= validFrom) {
					throw new Error('[did-provider-cheqd]: expirationDate must be after issuanceDate');
				}
			}
		} catch (error) {
			throw new Error(`[did-provider-cheqd]: Invalid date format: ${(error as Error).message}`);
		}
		// Validate status size if present
		if (metadata.statusSize !== undefined) {
			if (![1, 2, 4, 8].includes(metadata.statusSize)) {
				throw new Error('[did-provider-cheqd]: statusSize must be 1, 2, 4, or 8 bits');
			}

			// Validate status messages for multi-bit status
			if (metadata.statusSize > 1) {
				await this.validateStatusMessagesInPayload(metadata.statusMessages, metadata.statusSize);
			}
		}

		// Validate TTL if present
		if (bitstringCredential.credentialSubject.ttl !== undefined) {
			if (
				typeof bitstringCredential.credentialSubject.ttl !== 'number' ||
				bitstringCredential.credentialSubject.ttl < 0
			) {
				throw new Error('[did-provider-cheqd]: ttl must be a non-negative number');
			}
		}
	}

	/**
	 * Validate status messages for multi-bit status
	 */
	private async validateStatusMessagesInPayload(
		statusMessages: BitstringStatusMessage[] | undefined,
		statusSize: number
	): Promise<void> {
		if (statusSize <= 1) {
			return; // No validation needed for single-bit status
		}

		const expectedMessageCount = Math.pow(2, statusSize);

		if (!statusMessages || statusMessages.length === 0) {
			throw new Error(
				`[did-provider-cheqd]: statusMessages is required for ${statusSize}-bit status (expected ${expectedMessageCount} messages)`
			);
		}

		if (statusMessages.length !== expectedMessageCount) {
			throw new Error(
				`[did-provider-cheqd]: statusMessages must have exactly ${expectedMessageCount} entries for ${statusSize}-bit status`
			);
		}

		// Validate each status message
		const expectedStatuses = new Set<string>();
		for (let i = 0; i < expectedMessageCount; i++) {
			expectedStatuses.add(`0x${i.toString(16).toLowerCase()}`);
		}

		const actualStatuses = new Set(statusMessages.map((msg) => msg.status));

		for (const expected of expectedStatuses) {
			if (!actualStatuses.has(expected)) {
				throw new Error(`[did-provider-cheqd]: Missing status message for value ${expected}`);
			}
		}

		// Validate message format
		for (const statusMsg of statusMessages) {
			if (!statusMsg.status || !statusMsg.message) {
				throw new Error(
					'[did-provider-cheqd]: Each status message must have both status and message properties'
				);
			}

			if (typeof statusMsg.status !== 'string' || typeof statusMsg.message !== 'string') {
				throw new Error('[did-provider-cheqd]: status and message must be strings');
			}

			if (!statusMsg.status.match(/^0x[0-9a-f]+$/i)) {
				throw new Error(
					`[did-provider-cheqd]: Invalid status format ${statusMsg.status}. Must be hex prefixed with 0x`
				);
			}
		}
	}
	private async GenerateDidDoc(args: ICheqdGenerateDidDocArgs, context: IContext): Promise<TExportedDIDDocWithKeys> {
		if (typeof args.verificationMethod !== 'string') {
			throw new Error('[did-provider-cheqd]: verificationMethod is required');
		}

		if (typeof args.methodSpecificIdAlgo !== 'string') {
			throw new Error('[did-provider-cheqd]: methodSpecificIdAlgo is required');
		}

		if (typeof args.network !== 'string') {
			throw new Error('[did-provider-cheqd]: network is required');
		}

		const keyPair = createKeyPairBase64();
		const keyPairHex: IKeyPair = {
			publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'),
			privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex'),
		};
		const verificationKeys = createVerificationKeys(
			keyPair.publicKey,
			args.methodSpecificIdAlgo,
			'key-1',
			args.network
		);
		const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys]);

		return {
			didDoc: createDidPayload(verificationMethods, [verificationKeys]),
			versionId: v4(),
			keys: [
				{
					publicKeyHex: keyPairHex.publicKey,
					privateKeyHex: keyPairHex.privateKey,
					kid: keyPairHex.publicKey,
					type: 'Ed25519',
				},
			],
		};
	}

	private async GenerateDidDocWithLinkedResource(
		args: any,
		context: IContext
	): Promise<TExportedDIDDocWithLinkedResourceWithKeys> {
		if (typeof args.verificationMethod !== 'string') {
			throw new Error('[did-provider-cheqd]: verificationMethod is required');
		}

		if (typeof args.methodSpecificIdAlgo !== 'string') {
			throw new Error('[did-provider-cheqd]: methodSpecificIdAlgo is required');
		}

		if (typeof args.network !== 'string') {
			throw new Error('[did-provider-cheqd]: network is required');
		}

		const keyPair = createKeyPairBase64();
		const keyPairHex: IKeyPair = {
			publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'),
			privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex'),
		};
		const verificationKeys = createVerificationKeys(
			keyPair.publicKey,
			args.methodSpecificIdAlgo,
			'key-1',
			args.network
		);
		const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys]);
		const payload = createDidPayload(verificationMethods, [verificationKeys]);

		return {
			didDoc: payload,
			versionId: v4(),
			keys: [
				{
					publicKeyHex: keyPairHex.publicKey,
					privateKeyHex: keyPairHex.privateKey,
					kid: keyPairHex.publicKey,
					type: 'Ed25519',
				},
			],
			linkedResource: {
				id: v4(),
				collectionId: payload.id.split(':').reverse()[0],
				name: 'sample json resource',
				version: '1.0.0',
				resourceType: 'SampleResource',
				alsoKnownAs: [],
				data: toString(new TextEncoder().encode(JSON.stringify({ sample: 'json' })), 'base64'),
			},
		};
	}

	private async GenerateIdentityKeys(args: any, context: IContext): Promise<TImportableEd25519Key> {
		const keyPair = createKeyPairHex();
		return {
			publicKeyHex: keyPair.publicKey,
			privateKeyHex: keyPair.privateKey,
			kid: keyPair.publicKey,
			type: 'Ed25519',
		};
	}

	private async GenerateVersionId(args: any, context: IContext): Promise<string> {
		return v4();
	}

	private async GenerateStatusList2021(
		args: ICheqdGenerateStatusList2021Args,
		context: IContext
	): Promise<Bitstring> {
		const statusList = args?.buffer
			? new StatusList({ buffer: args.buffer })
			: new StatusList({ length: args?.length || Cheqd.defaultStatusList2021Length });

		const encoded = (await statusList.encode()) as Bitstring;

		switch (args?.bitstringEncoding) {
			case 'base64url':
				return encoded;
			case 'hex':
				return toString(fromString(encoded, 'base64url'), 'hex');
			default:
				return encoded;
		}
	}
	private async GenerateBitstringStatusList(args: ICheqdGenerateStatusListArgs, context: IContext): Promise<string> {
		const statusSize = args?.statusSize || 1; // default to 1 bit per entry // TODO change to 2 bits per entry after StatusList2021 is removed
		const length = args?.length || Cheqd.DefaultBitstringLength; // default to 131072
		// Total number of bits = entries * bits per entry
		const totalBits = length * statusSize;
		// Ensure bitstring is byte-aligned (i.e., multiple of 8 bits)
		const alignedLength = Math.ceil(totalBits / 8) * 8;

		const bitstring: DBBitstring = args?.buffer
			? new DBBitstring({ buffer: args.buffer })
			: new DBBitstring({ length: alignedLength });

		// get compressed bits
		const compressed = await bitstring.compressBits();
		switch (args?.bitstringEncoding) {
			case 'hex':
				return toString(compressed, 'hex');
			case 'base64url':
			default:
				return toString(compressed, 'base64url');
		}
	}

	private async VerifyStatusListCredential(
		args: ICheqdVerifyStatusListCredentialArgs,
		context: IContext
	): Promise<VerificationResult> {
		// if jwt credential, decode it
		const credentialObj =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;
		// Validate required fields
		if (!credentialObj || typeof credentialObj !== 'object') {
			return {
				verified: false,
				error: { message: 'Invalid credential format' },
			};
		}
		const { credentialSubject, ...rest } = credentialObj;
		// Validate credentialSubject and encodedList
		if (!credentialSubject?.encodedList) {
			return {
				verified: false,
				error: { message: 'Missing encodedList in credentialSubject' },
			};
		}
		// Validate that this is indeed a status list credential
		if (!credentialObj.type || !credentialObj.type.includes('BitstringStatusListCredential')) {
			return {
				verified: false,
				error: { message: 'Credential is not a BitstringStatusListCredential' },
			};
		}
		// Extract encodedList and create credential without it for verification
		const { encodedList, ...restCredentialSubject } = credentialSubject || {};
		// Create formatted credential for verification without encodedList
		const formattedCredential: VerifiableCredential = {
			credentialSubject: restCredentialSubject,
			...rest,
		};
		// verify default policies
		const verificationResult = await context.agent.verifyCredential({
			...args?.verificationArgs,
			credential: formattedCredential,
			policies: {
				...args?.verificationArgs?.policies,
				// Disable credentialStatus check for status list credentials to avoid circular dependency
				credentialStatus: false,
			},
		} satisfies IVerifyCredentialArgs);
		// Additional validation for BitstringStatusListCredential
		if (verificationResult.verified) {
			// Basic validation that encodedList is properly formatted
			if (typeof encodedList !== 'string' || !encodedList) {
				return {
					verified: false,
					error: { message: 'Invalid encodedList format' },
				};
			}
			// Validate encodedList format (should be base64url encoded)
			if (!isValidEncodedBitstring(encodedList)) {
				return {
					verified: false,
					error: { message: 'EncodedList validation failed' },
				};
			}

			// Validate statusPurpose is a valid value
			const statusPurpose = Array.isArray(credentialObj.credentialSubject.statusPurpose)
				? credentialObj.credentialSubject.statusPurpose[0]
				: credentialObj.credentialSubject.statusPurpose;
			if (!Object.values(BitstringStatusPurposeTypes).includes(statusPurpose)) {
				return {
					verified: false,
					error: { message: `Invalid statusPurpose: ${credentialObj.credentialSubject.statusPurpose}` },
				};
			}

			// If ttl is provided, validate it's a positive number
			if (
				restCredentialSubject.ttl !== undefined &&
				(typeof restCredentialSubject.ttl !== 'number' || restCredentialSubject.ttl <= 0)
			) {
				return {
					verified: false,
					error: { message: 'Invalid ttl value' },
				};
			}
		}

		return { verified: verificationResult.verified, error: verificationResult.error };
	}

	private async IssueCredentialWithBitstringStatusList(
		args: ICheqdIssueCredentialWithStatusListArgs,
		context: IContext
	): Promise<BitstringVerifiableCredential> {
		// validate resource type
		const allowedTypes: Array<'refresh' | 'message'> = ['refresh', 'message'];
		if (!allowedTypes.includes(args.statusOptions.statusPurpose as 'refresh' | 'message')) {
			throw new Error(
				`[did-provider-cheqd]: statusPurpose while issuance must be one of ${allowedTypes.join(', ')}`
			);
		}
		// construct issuer
		const issuer = (args.issuanceOptions.credential.issuer as { id: string }).id
			? (args.issuanceOptions.credential.issuer as { id: string }).id
			: (args.issuanceOptions.credential.issuer as string);
		// generate status list credential
		const statusListCredential = `${DefaultResolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}&resourceType=${BitstringStatusListResourceType}`;
		// get latest status list
		const statuslist = await Cheqd.fetchBitstringStatusList({
			credentialStatus: {
				id: statusListCredential,
			},
		} as VerifiableCredential);
		// Validate statusPurpose with statusList.statusPurpose
		const sl_statusPurpose = statuslist.bitstringStatusListCredential.credentialSubject.statusPurpose;
		if (!Object.values(sl_statusPurpose).includes(args.statusOptions.statusPurpose)) {
			throw new Error(
				`[did-provider-cheqd]: statusPurpose must be one of ${Object.values(sl_statusPurpose).join(', ')}`
			);
		}
		// If statusPurpose is 'message', statusMessages and statusSize MUST be present in Credential
		if (args.statusOptions.statusPurpose === BitstringStatusPurposeTypes.message) {
			if (!statuslist.metadata.statusSize || !statuslist.metadata.statusMessages) {
				throw new Error(
					'[did-provider-cheqd]: statusMessages and statusSize must be present for statusPurpose="message"'
				);
			}
		}

		// generate index
		const statusListIndex = await generateRandomStatusListIndex(args.statusOptions, {
			statusSize: statuslist.metadata.statusSize,
			length: statuslist.metadata.length,
		});

		// construct credential status
		const credentialStatus: BitstringStatusListEntry = {
			id: `${statusListCredential}#${statusListIndex}`,
			type: 'BitstringStatusListEntry',
			statusPurpose: args.statusOptions.statusPurpose || BitstringStatusPurposeTypes.message,
			statusListIndex: `${statusListIndex}`,
			statusListCredential,
			statusSize: statuslist.metadata.statusSize || 1,
			statusMessage: statuslist.metadata.statusMessages || [],
		};

		// add credential status to credential
		args.issuanceOptions.credential.credentialStatus = credentialStatus;

		// add relevant context
		args.issuanceOptions.credential['@context'] = this.addBitstringStatusListContexts(
			args.issuanceOptions.credential
		);
		// TODO: update Veramo so that default "https://www.w3.org/2018/credentials/v1" is not added in context
		// create a credential
		const credential = await context.agent.createVerifiableCredential(args.issuanceOptions);

		return credential as BitstringVerifiableCredential;
	}

	private async IssueRevocableCredentialWithStatusList2021(
		args: ICheqdIssueRevocableCredentialWithStatusList2021Args,
		context: IContext
	): Promise<VerifiableCredential> {
		// generate index
		const statusListIndex =
			args.statusOptions.statusListIndex ||
			(await randomFromRange(
				args.statusOptions.statusListRangeStart || 0,
				(args.statusOptions.statusListRangeEnd || Cheqd.defaultStatusList2021Length) - 1,
				args.statusOptions.indexNotIn || []
			));

		// construct issuer
		const issuer = (args.issuanceOptions.credential.issuer as { id: string }).id
			? (args.issuanceOptions.credential.issuer as { id: string }).id
			: (args.issuanceOptions.credential.issuer as string);

		// generate status list credential
		const statusListCredential = `${DefaultResolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.revocation}`;

		// construct credential status
		const credentialStatus = {
			id: `${statusListCredential}#${statusListIndex}`,
			type: 'StatusList2021Entry',
			statusPurpose: DefaultStatusList2021StatusPurposeTypes.revocation,
			statusListIndex: `${statusListIndex}`,
		};

		// add credential status to credential
		args.issuanceOptions.credential.credentialStatus = credentialStatus;

		// add relevant context
		args.issuanceOptions.credential['@context'] = this.addStatusList2021Contexts(args.issuanceOptions.credential);

		// create a credential
		const credential = await context.agent.createVerifiableCredential(args.issuanceOptions);

		return credential;
	}

	private async IssueSuspendableCredentialWithStatusList2021(
		args: ICheqdIssueSuspendableCredentialWithStatusList2021Args,
		context: IContext
	): Promise<VerifiableCredential> {
		// generate index
		const statusListIndex =
			args.statusOptions.statusListIndex ||
			(await randomFromRange(
				args.statusOptions.statusListRangeStart || 0,
				(args.statusOptions.statusListRangeEnd || Cheqd.defaultStatusList2021Length) - 1,
				args.statusOptions.indexNotIn || []
			));

		// construct issuer
		const issuer = (args.issuanceOptions.credential.issuer as { id: string }).id
			? (args.issuanceOptions.credential.issuer as { id: string }).id
			: (args.issuanceOptions.credential.issuer as string);

		// generate status list credential
		const statusListCredential = `${DefaultResolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.suspension}`;

		// construct credential status
		const credentialStatus = {
			id: `${statusListCredential}#${statusListIndex}`,
			type: 'StatusList2021Entry',
			statusPurpose: DefaultStatusList2021StatusPurposeTypes.suspension,
			statusListIndex: `${statusListIndex}`,
		};

		// add credential status to credential
		args.issuanceOptions.credential.credentialStatus = credentialStatus;

		// add relevant context
		args.issuanceOptions.credential['@context'] = this.addStatusList2021Contexts(args.issuanceOptions.credential);

		// create a credential
		const credential = await context.agent.createVerifiableCredential(args.issuanceOptions);

		return credential;
	}
	private addStatusList2021Contexts(credential: any): string[] {
		const contexts = credential['@context'] || [];
		// if context is provided as an array, add default context if it is not already present
		if (Array.isArray(contexts)) {
			const requiredContexts = [Cheqd.defaultContextV1, Cheqd.statusList2021Context];
			const missingContexts = requiredContexts.filter((ctx) => !contexts.includes(ctx));
			return [...contexts, ...missingContexts];
		}
		// if no context return default context
		return [Cheqd.defaultContextV1, Cheqd.statusList2021Context];
	}
	private addBitstringStatusListContexts(credential: any): string[] {
		const contexts = credential['@context'] || [];
		// if context is provided as an array, add default context if it is not already present
		if (Array.isArray(contexts)) {
			// TODO: Credential V1 context is used now, replace when V2 is implemented
			const requiredContexts = [Cheqd.defaultContextV1, Cheqd.DefaultBitstringContexts.statusList];
			const missingContexts = requiredContexts.filter((ctx) => !contexts.includes(ctx));
			return [...contexts, ...missingContexts];
		}
		// if no context return default context
		return [Cheqd.DefaultBitstringContexts.v2, Cheqd.DefaultBitstringContexts.statusList];
	}

	private async VerifyCredentialWithStatusList2021(
		args: ICheqdVerifyCredentialWithStatusListArgs,
		context: IContext
	): Promise<VerificationResult> {
		// verify default policies
		const verificationResult = await context.agent.verifyCredential({
			...args?.verificationArgs,
			credential: args.credential,
			policies: {
				...args?.verificationArgs?.policies,
				credentialStatus: false,
			},
		} satisfies IVerifyCredentialArgs);
		// early return if verification failed
		if (!verificationResult.verified) {
			return { verified: false, error: verificationResult.error };
		}

		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;

		// define issuer
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// verify credential status
		switch (credential.credentialStatus?.statusPurpose) {
			case DefaultStatusList2021StatusPurposeTypes.revocation:
				return {
					...verificationResult,
					revoked: await Cheqd.checkRevoked(credential, { ...args.options, topArgs: args }),
				};
			case DefaultStatusList2021StatusPurposeTypes.suspension:
				return {
					...verificationResult,
					suspended: await Cheqd.checkSuspended(credential, { ...args.options, topArgs: args }),
				};
			default:
				throw new Error(
					`[did-provider-cheqd]: verify credential: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
				);
		}
	}
	private async VerifyCredentialWithBitstringStatusList(
		args: ICheqdVerifyCredentialWithBitstringArgs,
		context: IContext
	): Promise<BitstringVerificationResult> {
		// verify default policies
		const verificationResult = await context.agent.verifyCredential({
			...args?.verificationArgs,
			credential: args.credential,
			policies: {
				...args?.verificationArgs?.policies,
				credentialStatus: false,
			},
		} satisfies IVerifyCredentialArgs);
		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;
		// early return if verification failed
		if (!verificationResult.verified) {
			return {
				verified: false,
				status: 1,
				purpose: credential.credentialStatus?.statusPurpose,
				valid: false,
				error: verificationResult.error,
			};
		}

		// define issuer
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// Fetch and verify the Bitstring status list VC
		let publishedList: BitstringStatusList;
		try {
			publishedList = await Cheqd.fetchBitstringStatusList({
				credentialStatus: {
					id: credential.credentialStatus?.statusListCredential,
				},
			} as VerifiableCredential);
		} catch {
			throw new Error('[did-provider-cheqd]: STATUS_RETRIEVAL_ERROR');
		}
		// Validate proof on the Bitstring status list VC
		const checkCredential = await this.VerifyStatusListCredential(
			{ credential: publishedList.bitstringStatusListCredential },
			context
		);
		if (!checkCredential.verified) {
			throw new Error('[did-provider-cheqd]: STATUS_VERIFICATION_ERROR');
		}
		const validationResult = await Cheqd.validateBitstringStatus(
			credential as BitstringVerifiableCredential,
			publishedList,
			{
				...args.options,
				topArgs: args,
				instantiateDkgClient: () => this.didProvider.instantiateDkgThresholdProtocolClient(),
			}
		);

		// verify credential status
		switch (credential.credentialStatus?.statusPurpose) {
			case BitstringStatusPurposeTypes.revocation:
				return {
					...verificationResult,
					revoked: !validationResult.valid,
					...validationResult,
				};
			case BitstringStatusPurposeTypes.suspension:
				return {
					...verificationResult,
					suspended: !validationResult.valid,
					...validationResult,
				};
			case BitstringStatusPurposeTypes.message:
			case BitstringStatusPurposeTypes.refresh:
				return { ...verificationResult, ...validationResult };
			default:
				throw new Error(
					`[did-provider-cheqd]: verify credential: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
				);
		}
	}

	static async validateBitstringStatus(
		vcToValidate: BitstringVerifiableCredential,
		publishedList: BitstringStatusList,
		options: ICheqdStatusListOptions = { fetchList: true }
	): Promise<BitstringValidationResult> {
		if (!vcToValidate?.credentialStatus) {
			throw new Error('[did-provider-cheqd]: CREDENTIAL_STATUS_MISSING');
		}

		// validate dkgOptions
		if (!options?.topArgs?.dkgOptions) {
			throw new Error('[did-provider-cheqd]: dkgOptions is required');
		}

		const statusEntry = vcToValidate.credentialStatus;
		const {
			statusPurpose,
			statusListIndex,
			statusSize = 1, // default to 1 if not given
		} = statusEntry;

		// Validate statusPurpose match in Bitstring statuslist VC
		const listSubject = publishedList?.bitstringStatusListCredential.credentialSubject;
		const purposesDeclared = Array.isArray(listSubject?.statusPurpose)
			? listSubject.statusPurpose
			: [listSubject?.statusPurpose];
		if (!purposesDeclared.includes(statusPurpose)) {
			throw new Error(
				"[did-provider-cheqd]: STATUS_VERIFICATION_ERROR 'statusPurpose' does not match Bitstring Status List 'statusPurpose'"
			);
		}

		// Extract and decompress the bitstring
		const encoded = listSubject?.encodedList;
		if (!encoded) {
			throw new Error('[did-provider-cheqd]: STATUS_LIST_MISSING_ENCODED');
		}
		// validate encoded list
		if (!isValidEncodedBitstring(encoded))
			throw new Error(
				'[did-provider-cheqd]: Invalid encodedList format. Must be base64url encoded GZIP compressed bitstring'
			);

		// fetch bitstring status list inscribed in credential
		const bitstringStatusList: string = await Cheqd.fetchAndDecryptBitstring(publishedList, options);

		// Expand bitstring and validate size
		const decompressedBuffer = await DBBitstring.decodeBits({ encoded: bitstringStatusList });
		const decompressedBitstring = new DBBitstring({ buffer: decompressedBuffer });
		const totalBits = decompressedBitstring.length;
		const numEntries = Math.floor(totalBits / statusSize);

		if (numEntries < Cheqd.DefaultBitstringLength) {
			throw new Error('[did-provider-cheqd]: STATUS_LIST_LENGTH_ERROR');
		}

		// Compute index
		const index = parseInt(statusListIndex, 10);
		const bitPosition = index * statusSize;

		if (bitPosition + statusSize > totalBits) {
			throw new Error('[did-provider-cheqd]: RANGE_ERROR');
		}

		const value = Cheqd.getBitValue(decompressedBitstring, bitPosition, statusSize);

		const result: BitstringValidationResult = {
			status: value,
			purpose: statusPurpose,
			valid: value === 0,
		};

		// Lookup statusMessage. if statusSize > 1
		const statusMessages = statusEntry.statusMessage;
		if (statusPurpose === BitstringStatusPurposeTypes.message && Array.isArray(statusMessages)) {
			const messageEntry = statusMessages.find((msg: any) => msg.status === `0x${value.toString(16)}`);
			if (messageEntry) {
				result.message = messageEntry.message;
			}
		}
		return result;
	}
	private async VerifyPresentationWithBitstringStatusList(
		args: ICheqdVerifyPresentationWithStatusListArgs,
		context: IContext
	): Promise<BitstringVerificationResult> {
		// Verify default presentation policies first
		const verificationResult = await context.agent.verifyPresentation({
			...args?.verificationArgs,
			presentation: args.presentation,
			policies: {
				...args?.verificationArgs?.policies,
				audience: false,
				credentialStatus: false, // We'll handle status verification separately
			},
		} satisfies IVerifyPresentationArgs);
		// Early return if basic presentation verification failed
		if (!verificationResult.verified) {
			return {
				verified: false,
				status: 1,
				purpose: 'unknown',
				valid: false,
				error: verificationResult.error,
			};
		}
		// Early return if no verifiable credentials are provided
		if (!args.presentation.verifiableCredential || !Array.isArray(args.presentation.verifiableCredential)) {
			throw new Error(
				'[did-provider-cheqd]: verify presentation: presentation.verifiableCredential is required and must be an array'
			);
		}
		if (args.presentation.verifiableCredential.length === 0) {
			throw new Error(
				'[did-provider-cheqd]: verify presentation: presentation must contain at least one verifiable credential'
			);
		}

		// Verify each credential's status
		const credentialResults: BitstringVerificationResult[] = [];
		let overallValid = true;
		let hasRevoked = false;
		let hasSuspended = false;

		for (let credential of args.presentation.verifiableCredential) {
			// If JWT credential, decode it
			if (typeof credential === 'string') {
				credential = await Cheqd.decodeCredentialJWT(credential);
			}

			// Skip credentials without status (they're considered valid)
			if (!credential.credentialStatus || credential.credentialStatus.type !== 'BitstringStatusListEntry') {
				credentialResults.push({
					verified: true,
					status: 0,
					purpose: 'none',
					valid: true,
				});
				continue;
			}
			try {
				// Define issuer for provider selection
				const issuer =
					typeof credential.issuer === 'string'
						? credential.issuer
						: (credential.issuer as { id: string }).id;
				// Define provider, if applicable
				this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);
				this.providerId = Cheqd.generateProviderId(issuer);
				args.dkgOptions ||= this.didProvider.dkgOptions;
				// Verify credential with Bitstring status list
				const credentialVerificationResult = await this.VerifyCredentialWithBitstringStatusList(
					{
						credential: credential as BitstringVerifiableCredential,
						verificationArgs: {
							...args?.verificationArgs,
							policies: {
								...args?.verificationArgs?.policies,
								credentialStatus: false, // We handle this manually
							},
							credential: '',
						},
						fetchList: args?.fetchList ?? true,
						dkgOptions: args.dkgOptions,
						options: args.options,
					},
					context
				);
				credentialResults.push(credentialVerificationResult);

				// Track overall status
				if (!credentialVerificationResult.verified || !credentialVerificationResult.valid) {
					overallValid = false;
				}
				switch (credentialVerificationResult.status) {
					case BitstringStatusValue.REVOKED:
						hasRevoked = true;
						overallValid = false;
						break;
					case BitstringStatusValue.SUSPENDED:
						hasSuspended = true;
						overallValid = false;
						break;
					default:
						hasSuspended = false;
						hasRevoked = false;
						overallValid = true;
				}
			} catch (error) {
				credentialResults.push({
					verified: false,
					status: 1,
					purpose: credential.credentialStatus?.statusPurpose || 'unknown',
					valid: false,
					error: error as IError,
				});
				overallValid = false;
			}
		}

		// Determine overall verification result
		const allCredentialsVerified = credentialResults.every((result) => result.verified);
		const overallVerified = verificationResult.verified && allCredentialsVerified;

		// Find the most significant status issue for reporting
		const firstFailedResult = credentialResults.find((result) => !result.verified || !result.valid);
		const resultStatus = firstFailedResult?.status ?? 0;
		const resultPurpose = firstFailedResult?.purpose ?? credentialResults[0]?.purpose ?? 'unknown';

		return {
			verified: overallVerified,
			status: resultStatus,
			purpose: resultPurpose,
			valid: overallValid,
			revoked: hasRevoked,
			suspended: hasSuspended,
			message: firstFailedResult?.message,
			error: firstFailedResult?.error,
		};
	}
	private async VerifyPresentationWithStatusList2021(
		args: ICheqdVerifyPresentationWithStatusListArgs,
		context: IContext
	): Promise<VerificationResult> {
		// verify default policies
		const verificationResult = await context.agent.verifyPresentation({
			...args?.verificationArgs,
			presentation: args.presentation,
			policies: {
				...args?.verificationArgs?.policies,
				credentialStatus: false,
			},
		} satisfies IVerifyPresentationArgs);

		// early return if verification failed
		if (!verificationResult.verified) {
			return { verified: false, error: verificationResult.error };
		}

		// early return if no verifiable credentials are provided
		if (!args.presentation.verifiableCredential)
			throw new Error('[did-provider-cheqd]: verify presentation: presentation.verifiableCredential is required');

		// verify credential(s) status(es)
		for (let credential of args.presentation.verifiableCredential) {
			// if jwt credential, decode it
			if (typeof credential === 'string') credential = await Cheqd.decodeCredentialJWT(credential);

			// define issuer
			const issuer =
				typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

			// define provider, if applicable
			this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

			// define provider id, if applicable
			this.providerId = Cheqd.generateProviderId(issuer);

			// define dkg options, if provided
			args.dkgOptions ||= this.didProvider.dkgOptions;

			switch (credential.credentialStatus?.statusPurpose) {
				case DefaultStatusList2021StatusPurposeTypes.revocation:
					return {
						...verificationResult,
						revoked: await Cheqd.checkRevoked(credential, { ...args.options, topArgs: args }),
					};
				case DefaultStatusList2021StatusPurposeTypes.suspension:
					return {
						...verificationResult,
						suspended: await Cheqd.checkSuspended(credential, { ...args.options, topArgs: args }),
					};
				default:
					throw new Error(
						`[did-provider-cheqd]: verify presentation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
					);
			}
		}

		return { ...verificationResult, verified: true };
	}

	private async CheckCredentialStatusWithStatusList2021(
		args: ICheqdCheckCredentialStatusWithStatusListArgs,
		context: IContext
	): Promise<StatusCheckResult> {
		// verify credential, if provided and status options are not
		if (args?.credential && !args?.statusOptions) {
			const verificationResult = await context.agent.verifyCredential({
				...args?.verificationOptions,
				credential: args.credential,
				policies: {
					credentialStatus: false,
				},
			} satisfies IVerifyCredentialArgs);

			// early return if verification failed
			if (!verificationResult.verified) {
				return { revoked: false, error: verificationResult.error };
			}
		}

		// if status options are provided, give precedence
		if (args?.statusOptions) {
			// validate status options - case: statusOptions.issuerDid
			if (!args.statusOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: check status: statusOptions.issuerDid is required');

			// validate status options - case: statusOptions.statusListName
			if (!args.statusOptions.statusListName)
				throw new Error('[did-provider-cheqd]: check status: statusOptions.statusListName is required');

			// validate status options - case: statusOptions.statusListIndex
			if (!args.statusOptions.statusPurpose)
				throw new Error('[did-provider-cheqd]: check status: statusOptions.statusListIndex is required');

			// validate status options - case: statusOptions.statusListIndex
			if (!args.statusOptions.statusListIndex)
				throw new Error('[did-provider-cheqd]: check status: statusOptions.statusListIndex is required');

			// generate resource type
			const resourceType =
				args.statusOptions.statusPurpose === DefaultStatusList2021StatusPurposeTypes.revocation
					? DefaultStatusList2021ResourceTypes.revocation
					: DefaultStatusList2021ResourceTypes.suspension;

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.statusOptions.issuerDid}?resourceName=${args.statusOptions.statusListName}&resourceType=${resourceType}`;

			// construct credential status
			args.credential = {
				'@context': [],
				issuer: args.statusOptions.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${args.statusOptions.statusListIndex}`,
					type: 'StatusList2021Entry',
					statusPurpose: `${args.statusOptions.statusPurpose}`,
					statusListIndex: `${args.statusOptions.statusListIndex}`,
				},
				issuanceDate: '',
				proof: {},
			};
		}

		// validate args - case: credential
		if (!args.credential) throw new Error('[did-provider-cheqd]: revocation: credential is required');

		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;

		// define issuer
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		switch (credential.credentialStatus?.statusPurpose) {
			case DefaultStatusList2021StatusPurposeTypes.revocation:
				return { revoked: await Cheqd.checkRevoked(credential, { ...args.options, topArgs: args }) };
			case DefaultStatusList2021StatusPurposeTypes.suspension:
				return { suspended: await Cheqd.checkSuspended(credential, { ...args.options, topArgs: args }) };
			default:
				throw new Error(
					`[did-provider-cheqd]: check status: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
				);
		}
	}
	private async UpdateCredentialWithStatusList(
		args: ICheqdUpdateCredentialWithStatusListArgs,
		context: IContext
	): Promise<BitstringUpdateResult> {
		// Validate args
		if (!args.credential) throw new Error('[did-provider-cheqd]: update: credential is required');
		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;
		// Verify credential if provided and update options are not
		if (args?.credential && !args?.updateOptions) {
			const verificationResult = await context.agent.verifyCredential({
				...args?.verificationOptions,
				credential: credential,
				policies: {
					credentialStatus: false,
				},
			} satisfies IVerifyCredentialArgs);

			if (!verificationResult.verified) {
				return {
					updated: false,
					statusValue: BitstringStatusValue.UNKNOWN,
					statusMessage: 'unknown',
					error: verificationResult.error,
				};
			}
		}
		if (typeof args.newStatus !== 'number' || args.newStatus < 0 || args.newStatus > 3)
			throw new Error(
				'[did-provider-cheqd]: updateOptions.newStatus must be 0-3 (valid/revoked/suspended/unknown)'
			);
		// if revocation options are provided, give precedence
		if (args?.updateOptions) {
			// Validate update options
			if (!args.updateOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: updateOptions.issuerDid is required');
			if (!args.updateOptions.statusListName)
				throw new Error('[did-provider-cheqd]: updateOptions.statusListName is required');
			if (typeof args.updateOptions.statusListIndex !== 'number')
				throw new Error('[did-provider-cheqd]: updateOptions.statusListIndex is required');

			// Construct status list credential URL
			const statusListCredential = `${DefaultResolverUrl}${args.updateOptions.issuerDid}?resourceName=${args.updateOptions.statusListName}&resourceType=${BitstringStatusListResourceType}`;

			// fetch latest status list
			const statusList = await Cheqd.fetchBitstringStatusList({
				credentialStatus: {
					id: statusListCredential,
				},
			} as VerifiableCredential);

			// For multi-purpose status lists, we need to determine the appropriate statusPurpose
			// based on the credential's current status entry or the new status being set
			const statusPurpose = this.getStatusPurposeForMultiPurposeList(args.newStatus);
			// construct credential status
			args.credential = {
				'@context': [],
				issuer: args.updateOptions.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${args.updateOptions.statusListIndex}`,
					type: 'BitstringStatusListEntry',
					statusPurpose: statusPurpose,
					statusListIndex: `${args.updateOptions.statusListIndex}`,
					statusListCredential,
					statusSize: statusList.metadata.statusSize || 1,
					statusMessage: statusList.metadata.statusMessages || [],
				},
				issuanceDate: '',
				proof: {},
			};
		}

		// Validate that this is a BitstringStatusListEntry
		if (credential.credentialStatus?.type !== 'BitstringStatusListEntry') {
			throw new Error('[did-provider-cheqd]: update: Credential must have BitstringStatusListEntry status');
		}

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: revocation: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: revocation: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: revocation: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: revocation: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// Define issuer and provider
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);
		this.providerId = Cheqd.generateProviderId(issuer);
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// Perform the status update
		return await Cheqd.updateBitstringCredentialStatus(credential, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				statusListEncoding: args?.options?.statusListEncoding,
				statusListValidUntil: args?.options?.statusListValidUntil,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}
	private getStatusPurposeForMultiPurposeList(newStatus: BitstringStatusValue): BitstringStatusListPurposeType {
		// TODO Add map with messages
		// Since the default status list supports multiple purposes, we can use any of them
		// For multi-purpose lists, typically 'message' is used as it's the most flexible
		return BitstringStatusPurposeTypes.message;
	}
	// Core status update logic for multi-purpose Bitstring Status Lists
	static async updateBitstringCredentialStatus(
		credential: VerifiableCredential,
		options?: ICheqdStatusListOptions
	): Promise<BitstringUpdateResult> {
		try {
			// Validate credential status
			if (!credential.credentialStatus) {
				throw new Error('[did-provider-cheqd]: update: Credential status is not present');
			}

			// Fetch published status list
			const publishedList = await Cheqd.fetchBitstringStatusList(credential);

			// Validate that this is a multi-purpose status list with 2-bit status
			if (publishedList.metadata.statusSize !== 2) {
				throw new Error('[did-provider-cheqd]: update: Status list must use 2-bit status size');
			}
			// Validate status messages are present for 2-bit status
			if (!publishedList.metadata.statusMessages || publishedList.metadata.statusMessages.length !== 4) {
				throw new Error(
					'[did-provider-cheqd]: update: Status list must have 4 status messages for 2-bit status'
				);
			}

			// Early return if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) {
				throw new Error('[did-provider-cheqd]: update: symmetricKey is required for encrypted status list');
			}
			// Calculate positions and values
			const statusIndex = parseInt(credential.credentialStatus.statusListIndex, 10);
			const statusSize = publishedList.metadata.statusSize; // Should be 2
			const newStatusValue = options?.topArgs.newStatus;

			// Fetch and decrypt the current bitstring
			const currentBitstring = await Cheqd.fetchAndDecryptBitstring(publishedList, options);
			// Parse the bitstring
			const decompressedBuffer = await DBBitstring.decodeBits({ encoded: currentBitstring });
			const bitstring = new DBBitstring({ buffer: decompressedBuffer });

			// Get current status value
			const bitPosition = statusIndex * statusSize;
			const currentStatusValue = Cheqd.getBitValue(bitstring, bitPosition, statusSize);

			// Check if update is needed
			if (currentStatusValue === newStatusValue) {
				const statusMessage =
					publishedList.metadata.statusMessages.find((msg) => parseInt(msg.status, 16) === currentStatusValue)
						?.message || 'unknown';

				return {
					updated: false,
					statusValue: currentStatusValue as BitstringStatusValue,
					statusMessage,
					error: { message: `Credential already has status value ${newStatusValue} (${statusMessage})` },
				};
			}

			// Update the bitstring
			Cheqd.setBitValue(bitstring, bitPosition, newStatusValue, statusSize);

			// Compress the updated bitstring
			const compressedBitstring = await bitstring.compressBits();
			const encodedBitstring = toString(compressedBitstring, 'base64url');

			// Create updated status list credential
			const updatedStatusListCredential = {
				...publishedList.bitstringStatusListCredential,
				credentialSubject: {
					...publishedList.bitstringStatusListCredential.credentialSubject,
					encodedList: encodedBitstring,
				},
			};

			const updatedStatusList: BitstringStatusList = {
				bitstringStatusListCredential: updatedStatusListCredential,
				metadata: publishedList.metadata,
			};

			// Write to file if requested
			if (options?.topArgs?.writeToFile) {
				await Cheqd.writeFile(compressedBitstring, options?.statusListFile);
			}

			// Publish if requested
			const published = options?.topArgs?.publish
				? await Cheqd.publishUpdatedBitstringStatusList(updatedStatusList, credential, options)
				: undefined;

			// Get status message for new value
			const newStatusMessage =
				publishedList.metadata.statusMessages.find((msg) => parseInt(msg.status, 16) === newStatusValue)
					?.message || 'unknown';

			const previousStatusMessage =
				publishedList.metadata.statusMessages.find((msg) => parseInt(msg.status, 16) === currentStatusValue)
					?.message || 'unknown';

			return {
				updated: true,
				statusValue: newStatusValue as BitstringStatusValue,
				previousStatusValue: currentStatusValue as BitstringStatusValue,
				statusMessage: newStatusMessage,
				published: options?.topArgs?.publish ? !!published : undefined,
				statusList: options?.topArgs?.returnUpdatedStatusList ? updatedStatusList : undefined,
				symmetricKey:
					options?.topArgs?.returnSymmetricKey && published?.symmetricKey
						? published.symmetricKey
						: undefined,
				resourceMetadata: options?.topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credential)
					: undefined,
			};
		} catch (error) {
			console.error('[did-provider-cheqd]: update error:', error);
			return {
				updated: false,
				statusValue: BitstringStatusValue.UNKNOWN,
				statusMessage: 'unknown',
				error: error as IError,
			};
		}
	}

	// Helper function to fetch and decrypt bitstring (same as before)
	static async fetchAndDecryptBitstring(
		publishedList: BitstringStatusList,
		options?: ICheqdStatusListOptions
	): Promise<string> {
		const topArgs = options?.topArgs as ICheqdUpdateCredentialWithStatusListArgs;
		const encoded = publishedList.bitstringStatusListCredential.credentialSubject.encodedList;
		if (topArgs?.fetchList) {
			// if not encrypted, return published bitstring (always base64url encoded)
			if (!publishedList.metadata.encrypted) {
				return encoded;
			}

			// otherwise, Decrypt using threshold encryption
			const { thresholdEncryptionCiphertext } = decodeWithMetadata(
				publishedList.bitstringStatusListCredential.credentialSubject.encodedList,
				publishedList.metadata.symmetricLength!
			);

			const lit = (await options!.instantiateDkgClient()) as LitProtocol;
			// construct access control conditions
			const unifiedAccessControlConditions = await Promise.all(
				publishedList.metadata.paymentConditions!.map(async (condition) => {
					switch (condition.type) {
						case AccessControlConditionTypes.timelockPayment:
							return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
								{
									key: '$.tx_responses.*.timestamp',
									comparator: '<=',
									value: `${condition.intervalInSeconds}`,
								},
								condition.feePaymentAmount,
								condition.feePaymentAddress,
								condition?.blockHeight,
								options?.topArgs?.dkgOptions?.chain
							);
						default:
							throw new Error(
								`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
							);
					}
				})
			);
			return await lit.decrypt(
				toString(thresholdEncryptionCiphertext, 'base64url'),
				publishedList.metadata.statusListHash!,
				unifiedAccessControlConditions
			);
		} else {
			// Use provided symmetric key or file
			if (options?.statusListFile) {
				// if not encrypted, return bitstring
				if (!publishedList.metadata.encrypted) {
					// construct encoded status list
					const bitstring = new DBBitstring({
						buffer: await Cheqd.getFile(options.statusListFile),
					});
					const compressed = await bitstring.compressBits();
					// validate against published list
					if (encoded !== toString(compressed, 'base64url'))
						throw new Error(
							'[did-provider-cheqd]: statusListFile does not match published Bitstring status list'
						);

					// return compressed
					return compressed;
				}
				// otherwise, decrypt and return bitstring
				const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));
				const decrypted = toString(
					await LitProtocol.decryptDirect(
						scopedRawBlob,
						await safeDeserialise(
							options?.topArgs?.symmetricKey,
							fromString,
							['hex'],
							'Invalid symmetric key'
						)
					),
					'base64url'
				);

				// validate against published list
				if (decrypted !== encoded)
					throw new Error(
						'[did-provider-cheqd]: statusListFile does not match published Bitstring status list'
					);

				// return decrypted
				return decrypted;
			}

			if (!options?.statusListInlineBitstring) {
				throw new Error(
					'[did-provider-cheqd]: statusListInlineBitstring required if statusListFile not provided'
				);
			}
			// validate against published list
			if (options?.statusListInlineBitstring !== encoded)
				throw new Error(
					'[did-provider-cheqd]: statusListInlineBitstring does not match published bitstring status list'
				);
			// otherwise, read from inline bitstring
			return options.statusListInlineBitstring;
		}
	}
	// Helper function to publish updated status list
	static async publishUpdatedBitstringStatusList(
		updatedStatusList: BitstringStatusList,
		credential: VerifiableCredential,
		options?: ICheqdStatusListOptions
	): Promise<{ symmetricKey?: string }> {
		const topArgs = options?.topArgs as ICheqdUpdateCredentialWithStatusListArgs;

		// Fetch current metadata
		const statusListMetadata = await Cheqd.fetchStatusListMetadata(credential);

		// Handle encrypted publishing if needed
		if (topArgs.publishEncrypted && updatedStatusList.metadata.encrypted) {
			// Re-encrypt with new content
			const bitstring = updatedStatusList.bitstringStatusListCredential.credentialSubject.encodedList;

			// Encrypt bitstring - case: symmetric
			const { encryptedString: symmetricEncryptionCiphertext, symmetricKey } = await LitProtocol.encryptDirect(
				fromString(bitstring, 'base64url')
			);

			// Get DKG client and encrypt threshold
			const lit = await options!.publishOptions.instantiateDkgClient();
			const unifiedAccessControlConditions = await Promise.all(
				updatedStatusList.metadata.paymentConditions!.map(async (condition) => {
					switch (condition.type) {
						case AccessControlConditionTypes.timelockPayment:
							return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
								{
									key: '$.tx_responses.*.timestamp',
									comparator: '<=',
									value: `${condition.intervalInSeconds}`,
								},
								condition.feePaymentAmount,
								condition.feePaymentAddress,
								condition?.blockHeight,
								topArgs?.dkgOptions?.chain
							);
						default:
							throw new Error(
								`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
							);
					}
				})
			);

			const { encryptedString: thresholdEncryptionCiphertext, stringHash } = await lit.encrypt(
				fromString(bitstring, 'base64url'),
				unifiedAccessControlConditions
			);

			// Update encoded list with encrypted content
			const { encodedList, symmetricLength } = await encodeWithMetadata(
				symmetricEncryptionCiphertext,
				thresholdEncryptionCiphertext
			);

			updatedStatusList.bitstringStatusListCredential.credentialSubject.encodedList = encodedList;
			updatedStatusList.metadata.statusListHash = stringHash;
			updatedStatusList.metadata.symmetricLength = symmetricLength;

			// Publish the encrypted status list
			await Cheqd.publishBitstringStatusList(
				fromString(JSON.stringify(updatedStatusList), 'utf-8'),
				statusListMetadata,
				options?.publishOptions
			);

			return { symmetricKey: toString(symmetricKey, 'hex') };
		} else {
			// Publish unencrypted
			await Cheqd.publishBitstringStatusList(
				fromString(JSON.stringify(updatedStatusList), 'utf-8'),
				statusListMetadata,
				options?.publishOptions
			);

			return {};
		}
	}
	// Helper function to publish bitstring status list
	static async publishBitstringStatusList(
		statusListRaw: Uint8Array,
		statusListMetadata: LinkedResourceMetadataResolutionResult,
		options: {
			context: IContext;
			resourceId?: string;
			resourceVersion?: string;
			resourceAlsoKnownAs?: AlternativeUri[];
			signInputs?: ISignInputs[];
			fee?: DidStdFee | 'auto' | number;
		}
	): Promise<boolean> {
		// Construct payload
		const payload = {
			id: options?.resourceId || v4(),
			collectionId: statusListMetadata.resourceCollectionId,
			name: statusListMetadata.resourceName,
			version: options?.resourceVersion || new Date().toISOString(),
			alsoKnownAs: options?.resourceAlsoKnownAs || [],
			resourceType: BitstringStatusListResourceType,
			data: statusListRaw,
		} satisfies BitstringStatusListResourcePayload;

		return await options.context.agent[BroadcastStatusListMethodName]({
			kms: (await options.context.agent.keyManagerGetKeyManagementSystems())[0],
			payload,
			network: statusListMetadata.resourceURI.split(':')[2] as CheqdNetwork,
			signInputs: options?.signInputs,
			fee: options?.fee,
		});
	}

	private async RevokeCredentialWithStatusList2021(
		args: ICheqdRevokeCredentialWithStatusListArgs,
		context: IContext
	): Promise<RevocationResult> {
		// verify credential, if provided and revocation options are not
		if (args?.credential && !args?.revocationOptions) {
			const verificationResult = await context.agent.verifyCredential({
				...args?.verificationOptions,
				credential: args.credential,
				policies: {
					credentialStatus: false,
				},
			} satisfies IVerifyCredentialArgs);

			// early return if verification failed
			if (!verificationResult.verified) {
				return { revoked: false, error: verificationResult.error };
			}
		}

		// if revocation options are provided, give precedence
		if (args?.revocationOptions) {
			// validate revocation options - case: revocationOptions.issuerDid
			if (!args.revocationOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: revocation: revocationOptions.issuerDid is required');

			// validate revocation options - case: revocationOptions.statusListName
			if (!args.revocationOptions.statusListName)
				throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListName is required');

			// validate revocation options - case: revocationOptions.statusListIndex
			if (!args.revocationOptions.statusListIndex)
				throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListIndex is required');

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.revocationOptions.issuerDid}?resourceName=${args.revocationOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.revocation}`;

			// construct credential status
			args.credential = {
				'@context': [],
				issuer: args.revocationOptions.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${args.revocationOptions.statusListIndex}`,
					type: 'StatusList2021Entry',
					statusPurpose: DefaultStatusList2021StatusPurposeTypes.revocation,
					statusListIndex: `${args.revocationOptions.statusListIndex}`,
				},
				issuanceDate: '',
				proof: {},
			};
		}

		// validate args - case: credential
		if (!args.credential) throw new Error('[did-provider-cheqd]: revocation: credential is required');

		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;

		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.revocation) {
			throw new Error(
				`[did-provider-cheqd]: revocation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: revocation: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: revocation: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: revocation: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: revocation: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// define issuer
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// revoke credential
		return await Cheqd.revokeCredential(credential, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				statusListEncoding: args?.options?.statusListEncoding,
				statusListValidUntil: args?.options?.statusListValidUntil,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}

	private async BulkUpdateCredentialsWithStatusList(
		args: ICheqdBulkUpdateCredentialWithStatusListArgs,
		context: IContext
	): Promise<BulkBitstringUpdateResult> {
		// verify credentials, if provided and update options are not
		if (args?.credentials && !args?.updateOptions) {
			const verificationResult = await Promise.all(
				args.credentials.map(async (credential) => {
					return await context.agent.verifyCredential({
						...args?.verificationOptions,
						credential,
						policies: {
							credentialStatus: false,
						},
					} satisfies IVerifyCredentialArgs);
				})
			);

			// early return if verification failed for any credential
			if (verificationResult.some((result) => !result.verified)) {
				return {
					updated: Array(args.credentials.length).fill(false),
					statusValues: Array(args.credentials.length).fill(BitstringStatusValue.UNKNOWN),
					statusMessages: Array(args.credentials.length).fill('verification failed'),
					error: verificationResult.find((result) => !result.verified)!.error || {
						message: 'verification: could not verify credential',
					},
				};
			}
		}
		// validate args - case: credentials
		if (!args.credentials || !args.credentials.length || args.credentials.length === 0) {
			throw new Error(
				'[did-provider-cheqd]: bulk update: credentials is required and must be an array of credentials'
			);
		}
		// validate new status value
		if (typeof args.newStatus !== 'number' || args.newStatus < 0 || args.newStatus > 3) {
			throw new Error(
				'[did-provider-cheqd]: bulk update: newStatus must be 0-3 (valid/revoked/suspended/unknown)'
			);
		}
		// if update options are provided, give precedence
		if (args?.updateOptions) {
			// validate update options
			if (!args.updateOptions.issuerDid) {
				throw new Error('[did-provider-cheqd]: bulk update: updateOptions.issuerDid is required');
			}
			if (!args.updateOptions.statusListName) {
				throw new Error('[did-provider-cheqd]: bulk update: updateOptions.statusListName is required');
			}
			if (!args.updateOptions.statusListIndices || !Array.isArray(args.updateOptions.statusListIndices)) {
				throw new Error(
					'[did-provider-cheqd]: bulk update: updateOptions.statusListIndices is required and must be an array'
				);
			}
			if (args.updateOptions.statusListIndices.length !== args.credentials.length) {
				throw new Error(
					'[did-provider-cheqd]: bulk update: statusListIndices length must match credentials length'
				);
			}

			// Construct status list credential URL
			const statusListCredential = `${DefaultResolverUrl}${args.updateOptions.issuerDid}?resourceName=${args.updateOptions.statusListName}&resourceType=${BitstringStatusListResourceType}`;

			// fetch latest status list to get metadata
			const statusList = await Cheqd.fetchBitstringStatusList({
				credentialStatus: {
					id: statusListCredential,
				},
			} as VerifiableCredential);

			// For multi-purpose status lists, determine the appropriate statusPurpose
			const statusPurpose = this.getStatusPurposeForMultiPurposeList(args.newStatus);

			// construct credentials with proper status entries
			args.credentials = args.updateOptions.statusListIndices.map((index, i) => ({
				'@context': [],
				issuer: args.updateOptions!.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${index}`,
					type: 'BitstringStatusListEntry',
					statusPurpose: statusPurpose,
					statusListIndex: `${index}`,
					statusListCredential,
					statusSize: statusList.metadata.statusSize || 1,
					statusMessage: statusList.metadata.statusMessages || [],
				},
				issuanceDate: '',
				proof: {},
			}));
		}
		// if jwt credentials, decode them
		const credentials = await Promise.all(
			args.credentials.map(async (credential) =>
				typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential
			)
		);
		// validate credentials - case: consistent issuer
		if (
			credentials
				.map((credential) => {
					return (credential.issuer as { id: string }).id
						? (credential.issuer as { id: string }).id
						: (credential.issuer as string);
				})
				.filter((value, _, self) => value && value !== self[0]).length > 0
		) {
			throw new Error('[did-provider-cheqd]: bulk update: Credentials must be issued by the same issuer');
		}
		// validate credentials - case: status list index uniqueness
		if (
			credentials
				.map((credential) => credential.credentialStatus!.statusListIndex)
				.filter((value, index, self) => self.indexOf(value) !== index).length > 0
		) {
			throw new Error('[did-provider-cheqd]: bulk update: Credentials must have unique status list index');
		}
		// validate credentials - case: status list credential consistency
		const statusListCredentialUrl = credentials[0].credentialStatus?.statusListCredential;
		if (!statusListCredentialUrl) {
			throw new Error('[did-provider-cheqd]: bulk update: Invalid status list credential URL');
		}
		if (
			!credentials.every(
				(credential) => credential.credentialStatus?.statusListCredential === statusListCredentialUrl
			)
		) {
			throw new Error('[did-provider-cheqd]: bulk update: Credentials must belong to the same status list');
		}
		// validate credentials - case: status list type
		if (!credentials.every((credential) => credential.credentialStatus?.type === 'BitstringStatusListEntry')) {
			throw new Error('[did-provider-cheqd]: bulk update: Invalid status list type');
		}

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: bulk update: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: bulk update: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: bulk update: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: bulk update: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}
		// Define issuer and provider
		const issuer =
			typeof credentials[0].issuer === 'string'
				? credentials[0].issuer
				: (credentials[0].issuer as { id: string }).id;

		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);
		this.providerId = Cheqd.generateProviderId(issuer);
		args.dkgOptions ||= this.didProvider.dkgOptions;
		try {
			// Fetch published status list
			const publishedList = await Cheqd.fetchBitstringStatusList(credentials[0]);
			// Error if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !args?.symmetricKey) {
				throw new Error(
					'[did-provider-cheqd]: bulk update: symmetricKey is required for encrypted status list'
				);
			}
			// Fetch and decrypt the current bitstring
			const currentBitstring = await Cheqd.fetchAndDecryptBitstring(publishedList, {
				...args.options,
				topArgs: args,
				instantiateDkgClient: () => this.didProvider.instantiateDkgThresholdProtocolClient(),
			});
			// Parse the bitstring
			const decompressedBuffer = await DBBitstring.decodeBits({ encoded: currentBitstring });
			const bitstring = new DBBitstring({ buffer: decompressedBuffer });

			const statusSize = publishedList.metadata.statusSize || Cheqd.DefaultBitstringStatusSize;
			const newStatusValue = args.newStatus;

			// Process all credentials
			const results: Array<{
				updated: boolean;
				statusValue: BitstringStatusValue;
				previousStatusValue?: BitstringStatusValue;
				statusMessage?: string;
			}> = [];

			let anyUpdated = false;
			for (const credential of credentials) {
				const statusIndex = parseInt(credential.credentialStatus!.statusListIndex, 10);
				const bitPosition = statusIndex * statusSize;

				// Get current status value
				const currentStatusValue = Cheqd.getBitValue(bitstring, bitPosition, statusSize);
				// Check if update is needed
				if (currentStatusValue === newStatusValue) {
					const statusMessage =
						publishedList.metadata.statusMessages?.find(
							(msg) => parseInt(msg.status, 16) === currentStatusValue
						)?.message || 'unknown';

					results.push({
						updated: false,
						statusValue: currentStatusValue as BitstringStatusValue,
						statusMessage,
					});
				} else {
					// Update the bitstring
					Cheqd.setBitValue(bitstring, bitPosition, newStatusValue, statusSize);

					const newStatusMessage =
						publishedList.metadata.statusMessages?.find(
							(msg) => parseInt(msg.status, 16) === newStatusValue
						)?.message || 'unknown';
					results.push({
						updated: true,
						statusValue: newStatusValue as BitstringStatusValue,
						previousStatusValue: currentStatusValue as BitstringStatusValue,
						statusMessage: newStatusMessage,
					});

					anyUpdated = true;
				}
			}
			// If no updates needed, return early
			if (!anyUpdated) {
				return {
					updated: results.map((r) => r.updated),
					statusValues: results.map((r) => r.statusValue),
					previousStatusValues: results.map((r) => r.previousStatusValue).filter((v) => v !== undefined),
					statusMessages: results.map((r) => r.statusMessage).filter((m) => m !== undefined),
				};
			}
			// Compress the updated bitstring
			const compressedBitstring = await bitstring.compressBits();
			const encodedBitstring = toString(compressedBitstring, 'base64url');

			// Create updated status list credential
			const updatedStatusListCredential = {
				...publishedList.bitstringStatusListCredential,
				credentialSubject: {
					...publishedList.bitstringStatusListCredential.credentialSubject,
					encodedList: encodedBitstring,
				},
			};

			const updatedStatusList: BitstringStatusList = {
				bitstringStatusListCredential: updatedStatusListCredential,
				metadata: publishedList.metadata,
			};
			// Write to file if requested
			if (args?.writeToFile) {
				await Cheqd.writeFile(compressedBitstring, args.options?.statusListFile);
			}
			// Publish if requested
			const published = args?.publish
				? await Cheqd.publishUpdatedBitstringStatusList(updatedStatusList, credentials[0], {
						...args.options,
						topArgs: args,
						publishOptions: {
							context,
							statusListEncoding: args?.options?.statusListEncoding,
							statusListValidUntil: args?.options?.statusListValidUntil,
							resourceId: args?.options?.resourceId,
							resourceVersion: args?.options?.resourceVersion,
							resourceAlsoKnownAs: args?.options?.alsoKnownAs,
							signInputs: args?.options?.signInputs,
							fee: args?.options?.fee,
							instantiateDkgClient: () => this.didProvider.instantiateDkgThresholdProtocolClient(),
						},
					})
				: undefined;
			return {
				updated: results.map((r) => r.updated),
				statusValues: results.map((r) => r.statusValue),
				previousStatusValues: results.map((r) => r.previousStatusValue).filter((v) => v !== undefined),
				statusMessages: results.map((r) => r.statusMessage).filter((m) => m !== undefined),
				published: args?.publish ? !!published : undefined,
				statusList: args?.returnUpdatedStatusList ? updatedStatusList : undefined,
				symmetricKey: args?.returnSymmetricKey && published?.symmetricKey ? published.symmetricKey : undefined,
				resourceMetadata: args?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credentials[0])
					: undefined,
			};
		} catch (error) {
			console.error('[did-provider-cheqd]: bulk update error:', error);
			return {
				updated: Array(credentials.length).fill(false),
				statusValues: Array(credentials.length).fill(BitstringStatusValue.UNKNOWN),
				statusMessages: Array(credentials.length).fill('update failed'),
				error: error as IError,
			};
		}
	}

	private async RevokeBulkCredentialsWithStatusList2021(
		args: ICheqdRevokeBulkCredentialsWithStatusListArgs,
		context: IContext
	): Promise<BulkRevocationResult> {
		// verify credential, if provided and revocation options are not
		if (args?.credentials && !args?.revocationOptions) {
			const verificationResult = await Promise.all(
				args.credentials.map(async (credential) => {
					return await context.agent.verifyCredential({
						...args?.verificationOptions,
						credential,
						policies: {
							credentialStatus: false,
						},
					} satisfies IVerifyCredentialArgs);
				})
			);

			// early return if verification failed for any credential
			if (verificationResult.some((result) => !result.verified)) {
				// define verified
				return {
					revoked: Array(args.credentials.length).fill(false),
					error: verificationResult.find((result) => !result.verified)!.error || {
						message: 'verification: could not verify credential',
					},
				};
			}
		}

		// if revocation options are provided, give precedence
		if (args?.revocationOptions) {
			// validate revocation options - case: revocationOptions.issuerDid
			if (!args.revocationOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: revocation: revocationOptions.issuerDid is required');

			// validate revocation options - case: revocationOptions.statusListName
			if (!args.revocationOptions.statusListName)
				throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListName is required');

			// validate revocation options - case: revocationOptions.statusListIndices
			if (
				!args.revocationOptions.statusListIndices ||
				!args.revocationOptions.statusListIndices.length ||
				args.revocationOptions.statusListIndices.length === 0 ||
				!args.revocationOptions.statusListIndices.every((index) => !isNaN(+index))
			)
				throw new Error(
					'[did-provider-cheqd]: revocation: revocationOptions.statusListIndex is required and must be an array of indices'
				);

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.revocationOptions.issuerDid}?resourceName=${args.revocationOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.revocation}`;

			// construct credential status
			args.credentials = args.revocationOptions.statusListIndices.map((index) => ({
				'@context': [],
				issuer: args.revocationOptions!.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${index}`,
					type: 'StatusList2021Entry',
					statusPurpose: DefaultStatusList2021StatusPurposeTypes.revocation,
					statusListIndex: `${index}`,
				},
				issuanceDate: '',
				proof: {},
			}));
		}

		// validate args - case: credentials
		if (!args.credentials || !args.credentials.length || args.credentials.length === 0)
			throw new Error(
				'[did-provider-cheqd]: revocation: credentials is required and must be an array of credentials'
			);

		// if jwt credentials, decode them
		const credentials = await Promise.all(
			args.credentials.map(async (credential) =>
				typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential
			)
		);

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: revocation: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: revocation: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: revocation: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: revocation: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// define issuer
		const issuer =
			typeof credentials[0].issuer === 'string'
				? credentials[0].issuer
				: (credentials[0].issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// revoke credentials
		return await Cheqd.revokeCredentials(credentials, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}

	private async SuspendCredentialWithStatusList2021(
		args: ICheqdSuspendCredentialWithStatusListArgs,
		context: IContext
	): Promise<SuspensionResult> {
		// verify credential, if provided and suspension options are not
		if (args?.credential && !args?.suspensionOptions) {
			const verificationResult = await context.agent.verifyCredential({
				...args?.verificationOptions,
				credential: args.credential,
				policies: {
					credentialStatus: false,
				},
			} satisfies IVerifyCredentialArgs);

			// early return if verification failed
			if (!verificationResult.verified) {
				return { suspended: false, error: verificationResult.error };
			}
		}

		// if suspension options are provided, give precedence
		if (args?.suspensionOptions) {
			// validate suspension options - case: suspensionOptions.issuerDid
			if (!args.suspensionOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.issuerDid is required');

			// validate suspension options - case: suspensionOptions.statusListName
			if (!args.suspensionOptions.statusListName)
				throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListName is required');

			// validate suspension options - case: suspensionOptions.statusListIndex
			if (!args.suspensionOptions.statusListIndex)
				throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListIndex is required');

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.suspensionOptions.issuerDid}?resourceName=${args.suspensionOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.suspension}`;

			// construct credential status
			args.credential = {
				'@context': [],
				issuer: args.suspensionOptions.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${args.suspensionOptions.statusListIndex}`,
					type: 'StatusList2021Entry',
					statusPurpose: DefaultStatusList2021StatusPurposeTypes.suspension,
					statusListIndex: `${args.suspensionOptions.statusListIndex}`,
				},
				issuanceDate: '',
				proof: {},
			};
		}

		// validate args - case: credential
		if (!args.credential) throw new Error('[did-provider-cheqd]: suspension: credential is required');

		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;

		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension) {
			throw new Error(
				`[did-provider-cheqd]: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: suspension: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: suspension: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: suspension: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: suspension: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// define issuer
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// suspend credential
		return await Cheqd.suspendCredential(credential, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				statusListEncoding: args?.options?.statusListEncoding,
				statusListValidUntil: args?.options?.statusListValidUntil,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}

	private async SuspendBulkCredentialsWithStatusList2021(
		args: ICheqdSuspendBulkCredentialsWithStatusListArgs,
		context: IContext
	): Promise<BulkSuspensionResult> {
		// verify credential, if provided and suspension options are not
		if (args?.credentials && !args?.suspensionOptions) {
			const verificationResult = await Promise.all(
				args.credentials.map(async (credential) => {
					return await context.agent.verifyCredential({
						...args?.verificationOptions,
						credential,
						policies: {
							credentialStatus: false,
						},
					} satisfies IVerifyCredentialArgs);
				})
			);

			// early return if verification failed for any credential
			if (verificationResult.some((result) => !result.verified)) {
				// define verified
				return {
					suspended: Array(args.credentials.length).fill(false),
					error: verificationResult.find((result) => !result.verified)!.error || {
						message: 'verification: could not verify credential',
					},
				};
			}
		}

		// if suspension options are provided, give precedence
		if (args?.suspensionOptions) {
			// validate suspension options - case: suspensionOptions.issuerDid
			if (!args.suspensionOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.issuerDid is required');

			// validate suspension options - case: suspensionOptions.statusListName
			if (!args.suspensionOptions.statusListName)
				throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListName is required');

			// validate suspension options - case: suspensionOptions.statusListIndices
			if (
				!args.suspensionOptions.statusListIndices ||
				!args.suspensionOptions.statusListIndices.length ||
				args.suspensionOptions.statusListIndices.length === 0 ||
				!args.suspensionOptions.statusListIndices.every((index) => !isNaN(+index))
			)
				throw new Error(
					'[did-provider-cheqd]: suspension: suspensionOptions.statusListIndex is required and must be an array of indices'
				);

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.suspensionOptions.issuerDid}?resourceName=${args.suspensionOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.suspension}`;

			// construct credential status
			args.credentials = args.suspensionOptions.statusListIndices.map((index) => ({
				'@context': [],
				issuer: args.suspensionOptions!.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${index}`,
					type: 'StatusList2021Entry',
					statusPurpose: DefaultStatusList2021StatusPurposeTypes.suspension,
					statusListIndex: `${index}`,
				},
				issuanceDate: '',
				proof: {},
			}));
		}

		// validate args - case: credentials
		if (!args.credentials || !args.credentials.length || args.credentials.length === 0)
			throw new Error(
				'[did-provider-cheqd]: suspension: credentials is required and must be an array of credentials'
			);

		// if jwt credentials, decode them
		const credentials = await Promise.all(
			args.credentials.map(async (credential) =>
				typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential
			)
		);

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: suspension: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: suspension: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: suspension: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: suspension: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// define issuer
		const issuer =
			typeof credentials[0].issuer === 'string'
				? credentials[0].issuer
				: (credentials[0].issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// suspend credentials
		return await Cheqd.suspendCredentials(credentials, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}

	private async UnsuspendCredentialWithStatusList2021(
		args: ICheqdUnsuspendCredentialWithStatusListArgs,
		context: IContext
	): Promise<UnsuspensionResult> {
		// verify credential, if provided and unsuspension options are not
		if (args?.credential && !args?.unsuspensionOptions) {
			const verificationResult = await context.agent.verifyCredential({
				...args?.verificationOptions,
				credential: args.credential,
				policies: {
					credentialStatus: false,
				},
			} satisfies IVerifyCredentialArgs);

			// early return if verification failed
			if (!verificationResult.verified) {
				return { unsuspended: false, error: verificationResult.error };
			}
		}

		// if unsuspension options are provided, give precedence
		if (args?.unsuspensionOptions) {
			// validate unsuspension options - case: unsuspensionOptions.issuerDid
			if (!args.unsuspensionOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.issuerDid is required');

			// validate unsuspension options - case: unsuspensionOptions.statusListName
			if (!args.unsuspensionOptions.statusListName)
				throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListName is required');

			// validate unsuspension options - case: unsuspensionOptions.statusListIndex
			if (!args.unsuspensionOptions.statusListIndex)
				throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListIndex is required');

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.unsuspensionOptions.issuerDid}?resourceName=${args.unsuspensionOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.suspension}`;

			// construct credential status
			args.credential = {
				'@context': [],
				issuer: args.unsuspensionOptions.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${args.unsuspensionOptions.statusListIndex}`,
					type: 'StatusList2021Entry',
					statusPurpose: DefaultStatusList2021StatusPurposeTypes.suspension,
					statusListIndex: `${args.unsuspensionOptions.statusListIndex}`,
				},
				issuanceDate: '',
				proof: {},
			};
		}

		// validate args - case: credential
		if (!args.credential) throw new Error('[did-provider-cheqd]: unsuspension: credential is required');

		// if jwt credential, decode it
		const credential =
			typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential;

		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension) {
			throw new Error(
				`[did-provider-cheqd]: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: suspension: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: suspension: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: suspension: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: suspension: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// define issuer
		const issuer =
			typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// suspend credential
		return await Cheqd.unsuspendCredential(credential, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				statusListEncoding: args?.options?.statusListEncoding,
				statusListValidUntil: args?.options?.statusListValidUntil,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}

	private async UnsuspendBulkCredentialsWithStatusList2021(
		args: ICheqdUnsuspendBulkCredentialsWithStatusListArgs,
		context: IContext
	): Promise<BulkUnsuspensionResult> {
		// verify credential, if provided and unsuspension options are not
		if (args?.credentials && !args?.unsuspensionOptions) {
			const verificationResult = await Promise.all(
				args.credentials.map(async (credential) => {
					return await context.agent.verifyCredential({
						...args?.verificationOptions,
						credential,
						policies: {
							credentialStatus: false,
						},
					} satisfies IVerifyCredentialArgs);
				})
			);

			// early return if verification failed for any credential
			if (verificationResult.some((result) => !result.verified)) {
				// define verified
				return {
					unsuspended: Array(args.credentials.length).fill(false),
					error: verificationResult.find((result) => !result.verified)!.error || {
						message: 'verification: could not verify credential',
					},
				};
			}
		}

		// if unsuspension options are provided, give precedence
		if (args?.unsuspensionOptions) {
			// validate unsuspension options - case: unsuspensionOptions.issuerDid
			if (!args.unsuspensionOptions.issuerDid)
				throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.issuerDid is required');

			// validate unsuspension options - case: unsuspensionOptions.statusListName
			if (!args.unsuspensionOptions.statusListName)
				throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListName is required');

			// validate unsuspension options - case: unsuspensionOptions.statusListIndices
			if (
				!args.unsuspensionOptions.statusListIndices ||
				!args.unsuspensionOptions.statusListIndices.length ||
				args.unsuspensionOptions.statusListIndices.length === 0 ||
				!args.unsuspensionOptions.statusListIndices.every((index) => !isNaN(+index))
			)
				throw new Error(
					'[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListIndex is required and must be an array of indices'
				);

			// construct status list credential
			const statusListCredential = `${DefaultResolverUrl}${args.unsuspensionOptions.issuerDid}?resourceName=${args.unsuspensionOptions.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes.suspension}`;

			// construct credential status
			args.credentials = args.unsuspensionOptions.statusListIndices.map((index) => ({
				'@context': [],
				issuer: args.unsuspensionOptions!.issuerDid,
				credentialSubject: {},
				credentialStatus: {
					id: `${statusListCredential}#${index}`,
					type: 'StatusList2021Entry',
					statusPurpose: DefaultStatusList2021StatusPurposeTypes.suspension,
					statusListIndex: `${index}`,
				},
				issuanceDate: '',
				proof: {},
			}));
		}

		// validate args - case: credentials
		if (!args.credentials || !args.credentials.length || args.credentials.length === 0)
			throw new Error(
				'[did-provider-cheqd]: unsuspension: credentials is required and must be an array of credentials'
			);

		// if jwt credentials, decode them
		const credentials = await Promise.all(
			args.credentials.map(async (credential) =>
				typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential
			)
		);

		// validate args in pairs - case: statusListFile and statusList
		if (args.options?.statusListFile && args.options?.statusList) {
			throw new Error('[did-provider-cheqd]: unsuspension: statusListFile and statusList are mutually exclusive');
		}

		// validate args in pairs - case: statusListFile and fetchList
		if (args.options?.statusListFile && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: unsuspension: statusListFile and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: statusList and fetchList
		if (args.options?.statusList && args.options?.fetchList) {
			throw new Error('[did-provider-cheqd]: unsuspension: statusList and fetchList are mutually exclusive');
		}

		// validate args in pairs - case: publish
		if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
			throw new Error(
				'[did-provider-cheqd]: unsuspension: publish requires statusListFile or statusList, if fetchList is disabled'
			);
		}

		// define issuer
		const issuer =
			typeof credentials[0].issuer === 'string'
				? credentials[0].issuer
				: (credentials[0].issuer as { id: string }).id;

		// define provider, if applicable
		this.didProvider = await Cheqd.getProviderFromDidUrl(issuer, this.supportedDidProviders);

		// define provider id, if applicable
		this.providerId = Cheqd.generateProviderId(issuer);

		// define dkg options, if provided
		args.dkgOptions ||= this.didProvider.dkgOptions;

		// suspend credentials
		return await Cheqd.unsuspendCredentials(credentials, {
			...args.options,
			topArgs: args,
			publishOptions: {
				context,
				resourceId: args?.options?.resourceId,
				resourceVersion: args?.options?.resourceVersion,
				resourceAlsoKnownAs: args?.options?.alsoKnownAs,
				signInputs: args?.options?.signInputs,
				fee: args?.options?.fee,
			},
		});
	}

	private async TransactSendTokens(
		args: ICheqdTransactSendTokensArgs,
		context: IContext
	): Promise<TransactionResult> {
		// define provider
		const provider = await Cheqd.getProviderFromNetwork(args.network, this.supportedDidProviders);

		try {
			// delegate to provider
			const transactionResult = await provider.transactSendTokens({
				recipientAddress: args.recipientAddress,
				amount: args.amount,
				memo: args.memo,
				txBytes: args.txBytes,
			});

			// return transaction result
			return {
				successful: !transactionResult.code,
				transactionHash: transactionResult.transactionHash,
				events: transactionResult.events,
				rawLog: transactionResult.rawLog,
				txResponse: args?.returnTxResponse ? transactionResult : undefined,
			} satisfies TransactionResult;
		} catch (error) {
			// return error
			return {
				successful: false,
				error: error as IError,
			} satisfies TransactionResult;
		}
	}

	private async ObservePaymentCondition(
		args: ICheqdObservePaymentConditionArgs,
		context: IContext
	): Promise<ObservationResult> {
		// verify with raw unified access control condition, if any
		if (args?.unifiedAccessControlCondition) {
			// validate args - case: unifiedAccessControlCondition.chain
			if (
				!args.unifiedAccessControlCondition.chain ||
				!Object.values(LitCompatibleCosmosChains).includes(
					args.unifiedAccessControlCondition.chain as LitCompatibleCosmosChain
				)
			)
				throw new Error(
					'[did-provider-cheqd]: observe: unifiedAccessControlCondition.chain is required and must be a valid Lit-compatible chain'
				);

			// validate args - case: unifiedAccessControlCondition.path
			if (!args.unifiedAccessControlCondition.path)
				throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.path is required');

			// validate args - case: unifiedAccessControlCondition.conditionType
			if (args.unifiedAccessControlCondition.conditionType !== 'cosmos')
				throw new Error(
					'[did-provider-cheqd]: observe: unifiedAccessControlCondition.conditionType must be cosmos'
				);

			// validate args - case: unifiedAccessControlCondition.method
			if (args.unifiedAccessControlCondition.method !== 'timelock')
				throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.method must be timelock');

			// validate args - case: unifiedAccessControlCondition.parameters
			if (
				!args.unifiedAccessControlCondition.parameters ||
				!Array.isArray(args.unifiedAccessControlCondition.parameters) ||
				args.unifiedAccessControlCondition.parameters.length === 0 ||
				args.unifiedAccessControlCondition.parameters.length > 1
			)
				throw new Error(
					'[did-provider-cheqd]: observe: unifiedAccessControlCondition.parameters is required and must be an array of length 1 of type string content'
				);

			// validate args - case: unifiedAccessControlCondition.returnValueTest
			if (
				!args.unifiedAccessControlCondition.returnValueTest ||
				!args.unifiedAccessControlCondition.returnValueTest.comparator ||
				!args.unifiedAccessControlCondition.returnValueTest.key ||
				!args.unifiedAccessControlCondition.returnValueTest.value
			)
				throw new Error(
					'[did-provider-cheqd]: observe: unifiedAccessControlCondition.returnValueTest is required'
				);

			try {
				// define network
				const network = (function () {
					switch (args.unifiedAccessControlCondition.chain) {
						case LitCompatibleCosmosChains.cheqdMainnet:
							return CheqdNetwork.Mainnet;
						case LitCompatibleCosmosChains.cheqdTestnet:
							return CheqdNetwork.Testnet;
						default:
							throw new Error(
								`[did-provider-cheqd]: observe: Unsupported chain: ${args.unifiedAccessControlCondition.chain}`
							);
					}
				})();

				// get block height url
				const blockHeightUrl = (function () {
					switch (args.unifiedAccessControlCondition.parameters[0]) {
						case 'latest':
							return `${DefaultRESTUrls[network]}/cosmos/base/tendermint/v1beta1/blocks/latest`;
						default:
							return `${DefaultRESTUrls[network]}/cosmos/base/tendermint/v1beta1/blocks/${args.unifiedAccessControlCondition.parameters[0]}`;
					}
				})();

				// fetch block response
				const blockHeightResponse = (await (await fetch(blockHeightUrl)).json()) as BlockResponse;

				// get timestamp from block response
				const blockTimestamp = Date.parse(blockHeightResponse.block.header.time);

				// construct url
				const url = `${DefaultRESTUrls[network]}${args.unifiedAccessControlCondition.path}`;

				// fetch relevant txs
				const txs = (await (await fetch(url)).json()) as ShallowTypedTxsResponse;

				// skim through txs for relevant events, in which case the transaction timestamp is within the defined interval in seconds, from the block timestamp
				const meetsConditionTxIndex = txs?.tx_responses?.findIndex((tx) => {
					// get tx timestamp
					const txTimestamp = Date.parse(tx.timestamp);

					// calculate diff in seconds
					const diffInSeconds = Math.floor((blockTimestamp - txTimestamp) / 1000);

					// return meets condition
					switch (args.unifiedAccessControlCondition!.returnValueTest.comparator) {
						case '<':
							return diffInSeconds < parseInt(args.unifiedAccessControlCondition!.returnValueTest.value);
						case '<=':
							return diffInSeconds <= parseInt(args.unifiedAccessControlCondition!.returnValueTest.value);
						default:
							throw new Error(
								`[did-provider-cheqd]: observe: Unsupported comparator: ${
									args.unifiedAccessControlCondition!.returnValueTest.comparator
								}`
							);
					}
				});

				// define meetsCondition
				const meetsCondition = typeof meetsConditionTxIndex !== 'undefined' && meetsConditionTxIndex !== -1;

				// return observation result
				return {
					subscribed: true,
					meetsCondition: meetsCondition,
					transactionHash: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].txhash : undefined,
					events: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].events : undefined,
					rawLog: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].raw_log : undefined,
					txResponse: meetsCondition
						? args?.returnTxResponse
							? txs!.tx_responses[meetsConditionTxIndex]
							: undefined
						: undefined,
				} satisfies ObservationResult;
			} catch (error) {
				// return error
				return {
					subscribed: false,
					meetsCondition: false,
					error: error as IError,
				} satisfies ObservationResult;
			}
		}

		// validate access control conditions components - case: recipientAddress
		if (!args.recipientAddress) {
			throw new Error('[did-provider-cheqd]: observation: recipientAddress is required');
		}

		// validate access control conditions components - case: amount
		if (!args.amount || !args.amount.amount || !args.amount.denom || args.amount.denom !== 'ncheq') {
			throw new Error(
				'[did-provider-cheqd]: observation: amount is required, and must be an object with amount and denom valid string properties, amongst which denom must be `ncheq`'
			);
		}

		// validate access control conditions components - case: intervalInSeconds
		if (!args.intervalInSeconds) {
			throw new Error('[did-provider-cheqd]: observation: intervalInSeconds is required');
		}

		// validate access control conditions components - case: comparator
		if (!args.comparator || (args.comparator !== '<' && args.comparator !== '<=')) {
			throw new Error('[did-provider-cheqd]: observation: comparator is required and must be either `<` or `<=`');
		}

		// validate access control conditions components - case: network
		if (!args.network) {
			throw new Error('[did-provider-cheqd]: observation: network is required');
		}

		// define block height, if not provided
		args.blockHeight ||= 'latest';

		try {
			// get block height url
			const blockHeightUrl = (function () {
				switch (args.blockHeight) {
					case 'latest':
						return `${DefaultRESTUrls[args.network]}/cosmos/base/tendermint/v1beta1/blocks/latest`;
					default:
						return `${DefaultRESTUrls[args.network]}/cosmos/base/tendermint/v1beta1/blocks/${
							args.blockHeight
						}`;
				}
			})();

			// fetch block response
			const blockHeightResponse = (await (await fetch(blockHeightUrl)).json()) as BlockResponse;

			// get timestamp from block response
			const blockTimestamp = Date.parse(blockHeightResponse.block.header.time);

			// otherwise, construct url, as per components
			const url = `${DefaultRESTUrls[args.network]}/cosmos/tx/v1beta1/txs?events=transfer.recipient='${
				args.recipientAddress
			}'&events=transfer.amount='${args.amount.amount}${args.amount.denom}'&order_by=2&pagination.limit=1`;

			// fetch relevant txs
			const txs = (await (await fetch(url)).json()) as ShallowTypedTxsResponse;

			// skim through txs for relevant events, in which case the transaction timestamp is within the defined interval in seconds, from the block timestamp
			const meetsConditionTxIndex = txs?.tx_responses?.findIndex((tx) => {
				// get tx timestamp
				const txTimestamp = Date.parse(tx.timestamp);

				// calculate diff in seconds
				const diffInSeconds = Math.floor((blockTimestamp - txTimestamp) / 1000);

				// return meets condition
				switch (args.comparator) {
					case '<':
						return diffInSeconds < args.intervalInSeconds!;
					case '<=':
						return diffInSeconds <= args.intervalInSeconds!;
					default:
						throw new Error(
							`[did-provider-cheqd]: observe: Unsupported comparator: ${
								args.unifiedAccessControlCondition!.returnValueTest.comparator
							}`
						);
				}
			});

			// define meetsCondition
			const meetsCondition = typeof meetsConditionTxIndex !== 'undefined' && meetsConditionTxIndex !== -1;

			// return observation result
			return {
				subscribed: true,
				meetsCondition: meetsCondition,
				transactionHash: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].txhash : undefined,
				events: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].events : undefined,
				rawLog: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].raw_log : undefined,
				txResponse: meetsCondition
					? args?.returnTxResponse
						? txs!.tx_responses[meetsConditionTxIndex]
						: undefined
					: undefined,
			} satisfies ObservationResult;
		} catch (error) {
			// return error
			return {
				subscribed: false,
				meetsCondition: false,
				error: error as IError,
			} satisfies ObservationResult;
		}
	}

	private async MintCapacityCredit(
		args: ICheqdMintCapacityCreditArgs,
		context: IContext
	): Promise<MintCapacityCreditResult> {
		// define provider
		const provider = await Cheqd.getProviderFromNetwork(args.network, this.supportedDidProviders);

		try {
			// delegate to provider
			const mintingResult = await provider.mintCapacityCredit({
				effectiveDays: args.effectiveDays,
				requestsPerDay: args.requestsPerDay,
				requestsPerSecond: args.requestsPerSecond,
				requestsPerKilosecond: args.requestsPerKilosecond,
			});

			// return mint result
			return {
				minted: true,
				...mintingResult,
			} satisfies MintCapacityCreditResult;
		} catch (error) {
			// return error
			return {
				minted: false,
				error: error as IError,
			} satisfies MintCapacityCreditResult;
		}
	}

	private async DelegateCapacityCredit(
		args: ICheqdDelegateCapacityCreditArgs,
		context: IContext
	): Promise<DelegateCapacityCreditResult> {
		// define provider
		const provider = await Cheqd.getProviderFromNetwork(args.network, this.supportedDidProviders);

		try {
			// delegate to provider
			const delegationResult = await provider.delegateCapacityCredit({
				capacityTokenId: args.capacityTokenId,
				delegateeAddresses: args.delegateeAddresses,
				uses: args.usesPermitted,
				expiration: args.expiration,
				statement: args.statement,
			});

			// return delegation result
			return {
				delegated: true,
				...delegationResult,
			} satisfies DelegateCapacityCreditResult;
		} catch (error) {
			// return error
			return {
				delegated: false,
				error: error as IError,
			} satisfies DelegateCapacityCreditResult;
		}
	}

	static async revokeCredential(
		credential: VerifiableCredential,
		options?: ICheqdStatusListOptions
	): Promise<RevocationResult> {
		try {
			// validate status purpose
			if (credential?.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.revocation)
				throw new Error('[did-provider-cheqd]: revocation: Invalid status purpose');

			// fetch status list 2021
			const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Revocation;

			// early return, if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey)
				throw new Error(
					'[did-provider-cheqd]: revocation: symmetricKey is required, if status list 2021 is encrypted'
				);

			// fetch status list 2021 inscribed in credential
			const statusList2021 = options?.topArgs?.fetchList
				? await (async function () {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted)
							return publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// decrypt + return bitstring, if qualified for migration
						if ((publishedList as StatusList2021RevocationNonMigrated).metadata.encryptedSymmetricKey)
							return await LitProtocolV2.decryptDirect(
								await toBlob(
									fromString(
										(publishedList as StatusList2021RevocationNonMigrated).StatusList2021
											.encodedList,
										'hex'
									)
								),
								fromString(options?.topArgs?.symmetricKey, 'hex')
							);

						// validate encoded list
						if (!isEncodedList(publishedList.StatusList2021.encodedList))
							throw new Error('[did-provider-cheqd]: revocation: Invalid encoded list');

						// otherwise, decrypt and return raw bitstring
						const scopedRawBlob = await toBlob(
							fromString(getEncodedList(publishedList.StatusList2021.encodedList, false)[0], 'hex')
						);

						// decrypt
						return toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);
					})()
				: await (async function () {
						// transcode to base64url, if needed
						const publishedListTranscoded =
							publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// if status list 2021 is not fetched, read from file
						if (options?.statusListFile) {
							// if not encrypted, return bitstring
							if (!publishedList.metadata.encrypted) {
								// construct encoded status list
								const encoded = new StatusList({
									buffer: await Cheqd.getFile(options.statusListFile),
								}).encode() as Bitstring;

								// validate against published list
								if (encoded !== publishedListTranscoded)
									throw new Error(
										'[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021'
									);

								// return encoded
								return encoded;
							}

							// otherwise, decrypt and return bitstring
							const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

							// decrypt
							const decrypted = toString(
								await LitProtocol.decryptDirect(
									scopedRawBlob,
									await safeDeserialise(
										options?.topArgs?.symmetricKey,
										fromString,
										['hex'],
										'Invalid symmetric key'
									)
								),
								'base64url'
							);

							// validate against published list
							if (decrypted !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021'
								);

							// return decrypted
							return decrypted;
						}

						if (!options?.statusListInlineBitstring)
							throw new Error(
								'[did-provider-cheqd]: revocation: statusListInlineBitstring is required, if statusListFile is not provided'
							);

						// validate against published list
						if (options?.statusListInlineBitstring !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: revocation: statusListInlineBitstring does not match published status list 2021'
							);

						// otherwise, read from inline bitstring
						return options?.statusListInlineBitstring;
					})();

			// parse status list 2021
			const statusList = await StatusList.decode({ encodedList: statusList2021 });

			// early exit, if credential is already revoked
			if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { revoked: true };

			// update revocation status
			statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true);

			// set in-memory status list ref
			const bitstring = (await statusList.encode()) as Bitstring;

			// cast top-level args
			const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusListArgs;

			// write status list 2021 to file, if provided
			if (topArgs?.writeToFile) {
				await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile);
			}

			// publish status list 2021, if provided
			const published = topArgs?.publish
				? await (async function () {
						// fetch status list 2021 metadata
						const statusListMetadata = await Cheqd.fetchStatusListMetadata(credential);

						// publish status list 2021 as new version
						const scoped = topArgs.publishEncrypted
							? await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: revocation: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// validate paymentConditions, if provided
									if (topArgs?.paymentConditions) {
										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.feePaymentAddress &&
													condition.feePaymentAmount &&
													condition.intervalInSeconds
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													typeof condition.feePaymentAddress === 'string' &&
													typeof condition.feePaymentAmount === 'string' &&
													typeof condition.intervalInSeconds === 'number'
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.type === AccessControlConditionTypes.timelockPayment
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must be of type timelockPayment'
											);
										}
									}

									// validate dkgOptions
									if (
										!topArgs?.dkgOptions ||
										!topArgs?.dkgOptions?.chain ||
										!topArgs?.dkgOptions?.network
									) {
										throw new Error('[did-provider-cheqd]: dkgOptions is required');
									}

									// encrypt bitstring - case: symmetric
									const {
										encryptedString: symmetricEncryptionCiphertext,
										stringHash: symmetricEncryptionStringHash,
										symmetricKey,
									} = await LitProtocol.encryptDirect(fromString(bitstring, 'base64url'));

									// instantiate dkg-threshold client, in which case lit-protocol is used
									const lit = (await options!.publishOptions.instantiateDkgClient) as LitProtocol;

									// construct access control conditions and payment conditions tuple
									const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
										? await (async function () {
												// define payment conditions, give precedence to top-level args
												const paymentConditions =
													topArgs?.paymentConditions ||
													publishedList.metadata.paymentConditions!;

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight,
																		topArgs?.dkgOptions?.chain
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})()
										: await (async function () {
												// validate paymentConditions
												if (!topArgs?.paymentConditions) {
													throw new Error(
														'[did-provider-cheqd]: paymentConditions is required'
													);
												}

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														topArgs.paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													topArgs.paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})();

									// encrypt bitstring - case: threshold
									const {
										encryptedString: thresholdEncryptionCiphertext,
										stringHash: thresholdEncryptionStringHash,
									} = await lit.encrypt(
										fromString(bitstring, 'base64url'),
										unifiedAccessControlConditionsTuple[0]
									);

									// construct encoded list
									const encodedList = `${await blobToHexString(
										symmetricEncryptionCiphertext
									)}-${toString(thresholdEncryptionCiphertext, 'hex')}`;

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList,
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encrypted: true,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											statusListHash:
												symmetricEncryptionStringHash === thresholdEncryptionStringHash
													? symmetricEncryptionStringHash
													: (function () {
															throw new Error(
																'[did-provider-cheqd]: revocation: symmetricEncryptionStringHash and thresholdEncryptionStringHash do not match'
															);
														})(),
											paymentConditions: unifiedAccessControlConditionsTuple[1],
										},
									} satisfies StatusList2021Revocation;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										{
											symmetricEncryptionCiphertext,
											thresholdEncryptionCiphertext,
											stringHash: symmetricEncryptionStringHash,
											symmetricKey,
										},
									];
								})()
							: await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: revocation: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList:
												publishedList.metadata.encoding === 'base64url'
													? bitstring
													: toString(
															fromString(bitstring, 'base64url'),
															options!.publishOptions
																.statusListEncoding as DefaultStatusListEncoding
														),
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											encrypted: false,
										},
									} satisfies StatusList2021Revocation;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										undefined,
									];
								})();

						// early exit, if publish failed
						if (!scoped[0])
							throw new Error('[did-provider-cheqd]: revocation: Failed to publish status list 2021');

						// return publish result
						return scoped;
					})()
				: undefined;

			return {
				revoked: true,
				published: topArgs?.publish ? true : undefined,
				statusList: topArgs?.returnUpdatedStatusList
					? ((await Cheqd.fetchStatusList2021(credential)) as StatusList2021Revocation)
					: undefined,
				symmetricKey: topArgs?.returnSymmetricKey
					? toString((published?.[1] as { symmetricKey: Uint8Array })?.symmetricKey, 'hex')
					: undefined,
				resourceMetadata: topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credential)
					: undefined,
			} satisfies RevocationResult;
		} catch (error) {
			// silent fail + early exit
			console.error(error);

			return { revoked: false, error: error as IError } satisfies RevocationResult;
		}
	}

	static async revokeCredentials(
		credentials: VerifiableCredential[],
		options?: ICheqdStatusListOptions
	): Promise<BulkRevocationResult> {
		// validate credentials - case: empty
		if (!credentials.length || credentials.length === 0)
			throw new Error('[did-provider-cheqd]: revocation: No credentials provided');

		// validate credentials - case: consistent issuer
		if (
			credentials
				.map((credential) => {
					return (credential.issuer as { id: string }).id
						? (credential.issuer as { id: string }).id
						: (credential.issuer as string);
				})
				.filter((value, _, self) => value && value !== self[0]).length > 0
		)
			throw new Error('[did-provider-cheqd]: revocation: Credentials must be issued by the same issuer');

		// validate credentials - case: status list index
		if (
			credentials
				.map((credential) => credential.credentialStatus!.statusListIndex)
				.filter((value, index, self) => self.indexOf(value) !== index).length > 0
		)
			throw new Error('[did-provider-cheqd]: revocation: Credentials must have unique status list index');

		// validate credentials - case: status purpose
		if (
			!credentials.every(
				(credential) =>
					credential.credentialStatus?.statusPurpose === DefaultStatusList2021StatusPurposeTypes.revocation
			)
		)
			throw new Error('[did-provider-cheqd]: revocation: Invalid status purpose');

		// validate credentials - case: status list id
		const remote = credentials[0].credentialStatus?.id
			? (credentials[0].credentialStatus as { id: string }).id.split('#')[0]
			: (function () {
					throw new Error('[did-provider-cheqd]: revocation: Invalid status list id');
				})();

		// validate credentials - case: status list id format
		if (!RemoteListPattern.test(remote))
			throw new Error(
				'[did-provider-cheqd]: revocation: Invalid status list id format: expected: https://<optional_subdomain>.<sld>.<tld>/1.0/identifiers/<did:cheqd:<namespace>:<method_specific_id>>?resourceName=<resource_name>&resourceType=<resource_type>'
			);

		if (
			!credentials.every((credential) => {
				return (credential.credentialStatus as { id: string }).id.split('#')[0] === remote;
			})
		)
			throw new Error('[did-provider-cheqd]: revocation: Credentials must belong to the same status list');

		// validate credentials - case: status list type
		if (!credentials.every((credential) => credential.credentialStatus?.type === 'StatusList2021Entry'))
			throw new Error('[did-provider-cheqd]: revocation: Invalid status list type');

		try {
			// fetch status list 2021
			const publishedList = (await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Revocation;

			// early return, if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey)
				throw new Error(
					'[did-provider-cheqd]: revocation: symmetricKey is required, if status list 2021 is encrypted'
				);

			// fetch status list 2021 inscribed in credential
			const statusList2021 = options?.topArgs?.fetchList
				? await (async function () {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted)
							return publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// decrypt + return bitstring, if qualified for migration
						if ((publishedList as StatusList2021RevocationNonMigrated).metadata.encryptedSymmetricKey)
							return await LitProtocolV2.decryptDirect(
								await toBlob(
									fromString(
										(publishedList as StatusList2021RevocationNonMigrated).StatusList2021
											.encodedList,
										'hex'
									)
								),
								fromString(options?.topArgs?.symmetricKey, 'hex')
							);

						// validate encoded list
						if (!isEncodedList(publishedList.StatusList2021.encodedList))
							throw new Error('[did-provider-cheqd]: revocation: Invalid encoded list');

						// otherwise, decrypt and return raw bitstring
						const scopedRawBlob = await toBlob(
							fromString(getEncodedList(publishedList.StatusList2021.encodedList, false)[0], 'hex')
						);

						// decrypt
						return toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);
					})()
				: await (async function () {
						// transcode to base64url, if needed
						const publishedListTranscoded =
							publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// if status list 2021 is not fetched, read from file
						if (options?.statusListFile) {
							// if not encrypted, return bitstring
							if (!publishedList.metadata.encrypted) {
								// construct encoded status list
								const encoded = new StatusList({
									buffer: await Cheqd.getFile(options.statusListFile),
								}).encode() as Bitstring;

								// validate against published list
								if (encoded !== publishedListTranscoded)
									throw new Error(
										'[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021'
									);

								// return encoded
								return encoded;
							}

							// otherwise, decrypt and return bitstring
							const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

							// decrypt
							const decrypted = toString(
								await LitProtocol.decryptDirect(
									scopedRawBlob,
									await safeDeserialise(
										options?.topArgs?.symmetricKey,
										fromString,
										['hex'],
										'Invalid symmetric key'
									)
								),
								'base64url'
							);

							// validate against published list
							if (decrypted !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021'
								);

							// return decrypted
							return decrypted;
						}

						if (!options?.statusListInlineBitstring)
							throw new Error(
								'[did-provider-cheqd]: revocation: statusListInlineBitstring is required, if statusListFile is not provided'
							);

						// validate against published list
						if (options?.statusListInlineBitstring !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: revocation: statusListInlineBitstring does not match published status list 2021'
							);

						// otherwise, read from inline bitstring
						return options?.statusListInlineBitstring;
					})();

			// parse status list 2021
			const statusList = await StatusList.decode({ encodedList: statusList2021 });

			// initiate bulk revocation
			const revoked = (await Promise.allSettled(
				credentials.map((credential) => {
					return (async function () {
						// early return, if no credential status
						if (!credential.credentialStatus) return { revoked: false };

						// early exit, if credential is already revoked
						if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex)))
							return { revoked: true };

						// update revocation status
						statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true);

						// return revocation status
						return { revoked: true };
					})();
				})
			)) satisfies PromiseSettledResult<RevocationResult>[];

			// revert bulk ops, if some failed
			if (revoked.some((result) => result.status === 'fulfilled' && !result.value.revoked))
				throw new Error(
					`[did-provider-cheqd]: revocation: Bulk revocation failed: already revoked credentials in revocation bundle: raw log: ${JSON.stringify(
						revoked.map((result) => ({
							revoked: result.status === 'fulfilled' ? result.value.revoked : false,
						}))
					)}`
				);

			// set in-memory status list ref
			const bitstring = (await statusList.encode()) as Bitstring;

			// cast top-level args
			const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusListArgs;

			// write status list 2021 to file, if provided
			if (topArgs?.writeToFile) {
				await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile);
			}

			// publish status list 2021, if provided
			const published = topArgs?.publish
				? await (async function () {
						// fetch status list 2021 metadata
						const statusListMetadata = await Cheqd.fetchStatusListMetadata(credentials[0]);

						// publish status list 2021 as new version
						const scoped = topArgs.publishEncrypted
							? await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: revocation: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// validate paymentConditions, if provided
									if (topArgs?.paymentConditions) {
										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.feePaymentAddress &&
													condition.feePaymentAmount &&
													condition.intervalInSeconds
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													typeof condition.feePaymentAddress === 'string' &&
													typeof condition.feePaymentAmount === 'string' &&
													typeof condition.intervalInSeconds === 'number'
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.type === AccessControlConditionTypes.timelockPayment
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must be of type timelockPayment'
											);
										}
									}

									// validate dkgOptions
									if (
										!topArgs?.dkgOptions ||
										!topArgs?.dkgOptions?.chain ||
										!topArgs?.dkgOptions?.network
									) {
										throw new Error('[did-provider-cheqd]: dkgOptions is required');
									}

									// encrypt bitstring - case: symmetric
									const {
										encryptedString: symmetricEncryptionCiphertext,
										stringHash: symmetricEncryptionStringHash,
										symmetricKey,
									} = await LitProtocol.encryptDirect(fromString(bitstring, 'base64url'));

									// instantiate dkg-threshold client, in which case lit-protocol is used
									const lit = (await options!.publishOptions.instantiateDkgClient) as LitProtocol;

									// construct access control conditions and payment conditions tuple
									const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
										? await (async function () {
												// define payment conditions, give precedence to top-level args
												const paymentConditions =
													topArgs?.paymentConditions ||
													publishedList.metadata.paymentConditions!;

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight,
																		topArgs?.dkgOptions?.chain
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})()
										: await (async function () {
												// validate paymentConditions
												if (!topArgs?.paymentConditions) {
													throw new Error(
														'[did-provider-cheqd]: paymentConditions is required'
													);
												}

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														topArgs.paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													topArgs.paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})();

									// encrypt bitstring - case: threshold
									const {
										encryptedString: thresholdEncryptionCiphertext,
										stringHash: thresholdEncryptionStringHash,
									} = await lit.encrypt(
										fromString(bitstring, 'base64url'),
										unifiedAccessControlConditionsTuple[0]
									);

									// construct encoded list
									const encodedList = `${await blobToHexString(
										symmetricEncryptionCiphertext
									)}-${toString(thresholdEncryptionCiphertext, 'hex')}`;

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList,
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encrypted: true,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											statusListHash:
												symmetricEncryptionStringHash === thresholdEncryptionStringHash
													? symmetricEncryptionStringHash
													: (function () {
															throw new Error(
																'[did-provider-cheqd]: revocation: symmetricEncryptionStringHash and thresholdEncryptionStringHash do not match'
															);
														})(),
											paymentConditions: unifiedAccessControlConditionsTuple[1],
										},
									} satisfies StatusList2021Revocation;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										{
											symmetricEncryptionCiphertext,
											thresholdEncryptionCiphertext,
											stringHash: symmetricEncryptionStringHash,
											symmetricKey,
										},
									];
								})()
							: await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: revocation: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList:
												publishedList.metadata.encoding === 'base64url'
													? bitstring
													: toString(
															fromString(bitstring, 'base64url'),
															options!.publishOptions
																.statusListEncoding as DefaultStatusListEncoding
														),
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											encrypted: false,
										},
									} satisfies StatusList2021Revocation;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										undefined,
									];
								})();

						// early exit, if publish failed
						if (!scoped[0])
							throw new Error('[did-provider-cheqd]: revocation: Failed to publish status list 2021');

						// return publish result
						return scoped;
					})()
				: undefined;

			return {
				revoked: revoked.map((result) => (result.status === 'fulfilled' ? result.value.revoked : false)),
				published: topArgs?.publish ? true : undefined,
				statusList: topArgs?.returnUpdatedStatusList
					? ((await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Revocation)
					: undefined,
				symmetricKey: topArgs?.returnSymmetricKey
					? toString((published?.[1] as { symmetricKey: Uint8Array })?.symmetricKey, 'hex')
					: undefined,
				resourceMetadata: topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credentials[0])
					: undefined,
			} satisfies BulkRevocationResult;
		} catch (error) {
			// silent fail + early exit
			console.error(error);

			return { revoked: [], error: error as IError } satisfies BulkRevocationResult;
		}
	}

	static async suspendCredential(
		credential: VerifiableCredential,
		options?: ICheqdStatusListOptions
	): Promise<SuspensionResult> {
		try {
			// validate status purpose
			if (credential?.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension)
				throw new Error('[did-provider-cheqd]: suspension: Invalid status purpose');

			// fetch status list 2021
			const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension;

			// early return, if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey)
				throw new Error(
					'[did-provider-cheqd]: suspension: symmetricKey is required, if status list 2021 is encrypted'
				);

			// fetch status list 2021 inscribed in credential
			const statusList2021 = options?.topArgs?.fetchList
				? await (async function () {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted)
							return publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// decrypt + return bitstring, if qualified for migration
						if ((publishedList as StatusList2021SuspensionNonMigrated).metadata.encryptedSymmetricKey)
							return await LitProtocolV2.decryptDirect(
								await toBlob(
									fromString(
										(publishedList as StatusList2021SuspensionNonMigrated).StatusList2021
											.encodedList,
										'hex'
									)
								),
								fromString(options?.topArgs?.symmetricKey, 'hex')
							);

						// validate encoded list
						if (!isEncodedList(publishedList.StatusList2021.encodedList))
							throw new Error('[did-provider-cheqd]: suspension: Invalid encoded list');

						// otherwise, decrypt and return raw bitstring
						const scopedRawBlob = await toBlob(
							fromString(getEncodedList(publishedList.StatusList2021.encodedList, false)[0], 'hex')
						);

						// decrypt
						return toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);
					})()
				: await (async function () {
						// transcode to base64url, if needed
						const publishedListTranscoded =
							publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// if status list 2021 is not fetched, read from file
						if (options?.statusListFile) {
							// if not encrypted, return bitstring
							if (!publishedList.metadata.encrypted) {
								// construct encoded status list
								const encoded = new StatusList({
									buffer: await Cheqd.getFile(options.statusListFile),
								}).encode() as Bitstring;

								// validate against published list
								if (encoded !== publishedListTranscoded)
									throw new Error(
										'[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021'
									);

								// return encoded
								return encoded;
							}

							// otherwise, decrypt and return bitstring
							const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

							// decrypt
							const decrypted = toString(
								await LitProtocol.decryptDirect(
									scopedRawBlob,
									await safeDeserialise(
										options?.topArgs?.symmetricKey,
										fromString,
										['hex'],
										'Invalid symmetric key'
									)
								),
								'base64url'
							);

							// validate against published list
							if (decrypted !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021'
								);

							// return decrypted
							return decrypted;
						}

						if (!options?.statusListInlineBitstring)
							throw new Error(
								'[did-provider-cheqd]: suspension: statusListInlineBitstring is required, if statusListFile is not provided'
							);

						// validate against published list
						if (options?.statusListInlineBitstring !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: suspension: statusListInlineBitstring does not match published status list 2021'
							);

						// otherwise, read from inline bitstring
						return options?.statusListInlineBitstring;
					})();

			// parse status list 2021
			const statusList = await StatusList.decode({ encodedList: statusList2021 });

			// early exit, if already suspended
			if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex)))
				return { suspended: true } satisfies SuspensionResult;

			// update suspension status
			statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true);

			// set in-memory status list ref
			const bitstring = (await statusList.encode()) as Bitstring;

			// cast top-level args
			const topArgs = options?.topArgs as ICheqdSuspendCredentialWithStatusListArgs;

			// write status list 2021 to file, if provided
			if (topArgs?.writeToFile) {
				await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile);
			}

			// publish status list 2021, if provided
			const published = topArgs?.publish
				? await (async function () {
						// fetch status list 2021 metadata
						const statusListMetadata = await Cheqd.fetchStatusListMetadata(credential);

						// publish status list 2021 as new version
						const scoped = topArgs.publishEncrypted
							? await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: suspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// validate paymentConditions, if provided
									if (topArgs?.paymentConditions) {
										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.feePaymentAddress &&
													condition.feePaymentAmount &&
													condition.intervalInSeconds
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													typeof condition.feePaymentAddress === 'string' &&
													typeof condition.feePaymentAmount === 'string' &&
													typeof condition.intervalInSeconds === 'number'
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.type === AccessControlConditionTypes.timelockPayment
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must be of type timelockPayment'
											);
										}
									}

									// validate dkgOptions
									if (
										!topArgs?.dkgOptions ||
										!topArgs?.dkgOptions?.chain ||
										!topArgs?.dkgOptions?.network
									) {
										throw new Error('[did-provider-cheqd]: dkgOptions is required');
									}

									// encrypt bitstring - case: symmetric
									const {
										encryptedString: symmetricEncryptionCiphertext,
										stringHash: symmetricEncryptionStringHash,
										symmetricKey,
									} = await LitProtocol.encryptDirect(fromString(bitstring, 'base64url'));

									// instantiate dkg-threshold client, in which case lit-protocol is used
									const lit = (await options!.publishOptions.instantiateDkgClient) as LitProtocol;

									// construct access control conditions and payment conditions tuple
									const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
										? await (async function () {
												// define payment conditions, give precedence to top-level args
												const paymentConditions =
													topArgs?.paymentConditions ||
													publishedList.metadata.paymentConditions!;

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight,
																		topArgs?.dkgOptions?.chain
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})()
										: await (async function () {
												// validate paymentConditions
												if (!topArgs?.paymentConditions) {
													throw new Error(
														'[did-provider-cheqd]: paymentConditions is required'
													);
												}

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														topArgs.paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													topArgs.paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})();

									// encrypt bitstring - case: threshold
									const {
										encryptedString: thresholdEncryptionCiphertext,
										stringHash: thresholdEncryptionStringHash,
									} = await lit.encrypt(
										fromString(bitstring, 'base64url'),
										unifiedAccessControlConditionsTuple[0]
									);

									// construct encoded list
									const encodedList = `${await blobToHexString(
										symmetricEncryptionCiphertext
									)}-${toString(thresholdEncryptionCiphertext, 'hex')}`;

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList,
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encrypted: true,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											statusListHash:
												symmetricEncryptionStringHash === thresholdEncryptionStringHash
													? symmetricEncryptionStringHash
													: (function () {
															throw new Error(
																'[did-provider-cheqd]: suspension: symmetricEncryptionStringHash and thresholdEncryptionStringHash do not match'
															);
														})(),
											paymentConditions: unifiedAccessControlConditionsTuple[1],
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										{
											symmetricEncryptionCiphertext,
											thresholdEncryptionCiphertext,
											stringHash: symmetricEncryptionStringHash,
											symmetricKey,
										},
									];
								})()
							: await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: suspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList:
												publishedList.metadata.encoding === 'base64url'
													? bitstring
													: toString(
															fromString(bitstring, 'base64url'),
															options!.publishOptions
																.statusListEncoding as DefaultStatusListEncoding
														),
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											encrypted: false,
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										undefined,
									];
								})();

						// early exit, if publish failed
						if (!scoped[0])
							throw new Error('[did-provider-cheqd]: suspension: Failed to publish status list 2021');

						// return publish result
						return scoped;
					})()
				: undefined;

			return {
				suspended: true,
				published: topArgs?.publish ? true : undefined,
				statusList: topArgs?.returnUpdatedStatusList
					? ((await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension)
					: undefined,
				symmetricKey: topArgs?.returnSymmetricKey
					? toString((published?.[1] as { symmetricKey: Uint8Array })?.symmetricKey, 'hex')
					: undefined,
				resourceMetadata: topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credential)
					: undefined,
			} satisfies SuspensionResult;
		} catch (error) {
			// silent fail + early exit
			console.error(error);

			return { suspended: false, error: error as IError } satisfies SuspensionResult;
		}
	}

	static async suspendCredentials(
		credentials: VerifiableCredential[],
		options?: ICheqdStatusListOptions
	): Promise<BulkSuspensionResult> {
		// validate credentials - case: empty
		if (!credentials.length || credentials.length === 0)
			throw new Error('[did-provider-cheqd]: suspension: No credentials provided');

		// validate credentials - case: consistent issuer
		if (
			credentials
				.map((credential) => {
					return (credential.issuer as { id: string }).id
						? (credential.issuer as { id: string }).id
						: (credential.issuer as string);
				})
				.filter((value, _, self) => value && value !== self[0]).length > 0
		)
			throw new Error('[did-provider-cheqd]: suspension: Credentials must be issued by the same issuer');

		// validate credentials - case: status list index
		if (
			credentials
				.map((credential) => credential.credentialStatus!.statusListIndex)
				.filter((value, index, self) => self.indexOf(value) !== index).length > 0
		)
			throw new Error('[did-provider-cheqd]: suspension: Credentials must have unique status list index');

		// validate credentials - case: status purpose
		if (
			!credentials.every(
				(credential) =>
					credential.credentialStatus?.statusPurpose === DefaultStatusList2021StatusPurposeTypes.suspension
			)
		)
			throw new Error('[did-provider-cheqd]: suspension: Invalid status purpose');

		// validate credentials - case: status list id
		const remote = credentials[0].credentialStatus?.id
			? (credentials[0].credentialStatus as { id: string }).id.split('#')[0]
			: (function () {
					throw new Error('[did-provider-cheqd]: suspension: Invalid status list id');
				})();

		// validate credentials - case: status list id format
		if (!RemoteListPattern.test(remote))
			throw new Error(
				'[did-provider-cheqd]: suspension: Invalid status list id format: expected: https://<optional_subdomain>.<sld>.<tld>/1.0/identifiers/<did:cheqd:<namespace>:<method_specific_id>>?resourceName=<resource_name>&resourceType=<resource_type>'
			);

		if (
			!credentials.every((credential) => {
				return (credential.credentialStatus as { id: string }).id.split('#')[0] === remote;
			})
		)
			throw new Error('[did-provider-cheqd]: suspension: Credentials must belong to the same status list');

		// validate credentials - case: status list type
		if (!credentials.every((credential) => credential.credentialStatus?.type === 'StatusList2021Entry'))
			throw new Error('[did-provider-cheqd]: suspension: Invalid status list type');

		try {
			// fetch status list 2021
			const publishedList = (await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Suspension;

			// early return, if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey)
				throw new Error(
					'[did-provider-cheqd]: suspension: symmetricKey is required, if status list 2021 is encrypted'
				);

			// fetch status list 2021 inscribed in credential
			const statusList2021 = options?.topArgs?.fetchList
				? await (async function () {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted)
							return publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// decrypt + return bitstring, if qualified for migration
						if ((publishedList as StatusList2021SuspensionNonMigrated).metadata.encryptedSymmetricKey)
							return await LitProtocolV2.decryptDirect(
								await toBlob(
									fromString(
										(publishedList as StatusList2021SuspensionNonMigrated).StatusList2021
											.encodedList,
										'hex'
									)
								),
								fromString(options?.topArgs?.symmetricKey, 'hex')
							);

						// validate encoded list
						if (!isEncodedList(publishedList.StatusList2021.encodedList))
							throw new Error('[did-provider-cheqd]: suspension: Invalid encoded list');

						// otherwise, decrypt and return raw bitstring
						const scopedRawBlob = await toBlob(
							fromString(getEncodedList(publishedList.StatusList2021.encodedList, false)[0], 'hex')
						);

						// decrypt
						return toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);
					})()
				: await (async function () {
						// transcode to base64url, if needed
						const publishedListTranscoded =
							publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// if status list 2021 is not fetched, read from file
						if (options?.statusListFile) {
							// if not encrypted, return bitstring
							if (!publishedList.metadata.encrypted) {
								// construct encoded status list
								const encoded = new StatusList({
									buffer: await Cheqd.getFile(options.statusListFile),
								}).encode() as Bitstring;

								// validate against published list
								if (encoded !== publishedListTranscoded)
									throw new Error(
										'[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021'
									);

								// return encoded
								return encoded;
							}

							// otherwise, decrypt and return bitstring
							const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

							// decrypt
							const decrypted = toString(
								await LitProtocol.decryptDirect(
									scopedRawBlob,
									await safeDeserialise(
										options?.topArgs?.symmetricKey,
										fromString,
										['hex'],
										'Invalid symmetric key'
									)
								),
								'base64url'
							);

							// validate against published list
							if (decrypted !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021'
								);

							// return decrypted
							return decrypted;
						}

						if (!options?.statusListInlineBitstring)
							throw new Error(
								'[did-provider-cheqd]: suspension: statusListInlineBitstring is required, if statusListFile is not provided'
							);

						// validate against published list
						if (options?.statusListInlineBitstring !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: suspension: statusListInlineBitstring does not match published status list 2021'
							);

						// otherwise, read from inline bitstring
						return options?.statusListInlineBitstring;
					})();

			// parse status list 2021
			const statusList = await StatusList.decode({ encodedList: statusList2021 });

			// initiate bulk suspension
			const suspended = (await Promise.allSettled(
				credentials.map((credential) => {
					return (async function () {
						// early return, if no credential status
						if (!credential.credentialStatus) return { suspended: false };

						// early exit, if credential is already suspended
						if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex)))
							return { suspended: true };

						// update suspension status
						statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true);

						// return suspension status
						return { suspended: true };
					})();
				})
			)) satisfies PromiseSettledResult<SuspensionResult>[];

			// revert bulk ops, if some failed
			if (suspended.some((result) => result.status === 'fulfilled' && !result.value.suspended))
				throw new Error(
					`[did-provider-cheqd]: suspension: Bulk suspension failed: already suspended credentials in suspension bundle: raw log: ${JSON.stringify(
						suspended.map((result) => ({
							suspended: result.status === 'fulfilled' ? result.value.suspended : false,
						}))
					)}`
				);

			// set in-memory status list ref
			const bitstring = (await statusList.encode()) as Bitstring;

			// cast top-level args
			const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusListArgs;

			// write status list 2021 to file, if provided
			if (topArgs?.writeToFile) {
				await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile);
			}

			// publish status list 2021, if provided
			const published = topArgs?.publish
				? await (async function () {
						// fetch status list 2021 metadata
						const statusListMetadata = await Cheqd.fetchStatusListMetadata(credentials[0]);

						// publish status list 2021 as new version
						const scoped = topArgs.publishEncrypted
							? await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: suspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// validate paymentConditions, if provided
									if (topArgs?.paymentConditions) {
										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.feePaymentAddress &&
													condition.feePaymentAmount &&
													condition.intervalInSeconds
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													typeof condition.feePaymentAddress === 'string' &&
													typeof condition.feePaymentAmount === 'string' &&
													typeof condition.intervalInSeconds === 'number'
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.type === AccessControlConditionTypes.timelockPayment
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must be of type timelockPayment'
											);
										}
									}

									// validate dkgOptions
									if (
										!topArgs?.dkgOptions ||
										!topArgs?.dkgOptions?.chain ||
										!topArgs?.dkgOptions?.network
									) {
										throw new Error('[did-provider-cheqd]: dkgOptions is required');
									}

									// encrypt bitstring - case: symmetric
									const {
										encryptedString: symmetricEncryptionCiphertext,
										stringHash: symmetricEncryptionStringHash,
										symmetricKey,
									} = await LitProtocol.encryptDirect(fromString(bitstring, 'base64url'));

									// instantiate dkg-threshold client, in which case lit-protocol is used
									const lit = (await options!.publishOptions.instantiateDkgClient) as LitProtocol;

									// construct access control conditions and payment conditions tuple
									const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
										? await (async function () {
												// define payment conditions, give precedence to top-level args
												const paymentConditions =
													topArgs?.paymentConditions ||
													publishedList.metadata.paymentConditions!;

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight,
																		topArgs?.dkgOptions?.chain
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})()
										: await (async function () {
												// validate paymentConditions
												if (!topArgs?.paymentConditions) {
													throw new Error(
														'[did-provider-cheqd]: paymentConditions is required'
													);
												}

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														topArgs.paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													topArgs.paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})();

									// encrypt bitstring - case: threshold
									const {
										encryptedString: thresholdEncryptionCiphertext,
										stringHash: thresholdEncryptionStringHash,
									} = await lit.encrypt(
										fromString(bitstring, 'base64url'),
										unifiedAccessControlConditionsTuple[0]
									);

									// construct encoded list
									const encodedList = `${await blobToHexString(
										symmetricEncryptionCiphertext
									)}-${toString(thresholdEncryptionCiphertext, 'hex')}`;

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList,
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encrypted: true,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											statusListHash:
												symmetricEncryptionStringHash === thresholdEncryptionStringHash
													? symmetricEncryptionStringHash
													: (function () {
															throw new Error(
																'[did-provider-cheqd]: suspension: symmetricEncryptionStringHash and thresholdEncryptionStringHash do not match'
															);
														})(),
											paymentConditions: unifiedAccessControlConditionsTuple[1],
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										{
											symmetricEncryptionCiphertext,
											thresholdEncryptionCiphertext,
											stringHash: symmetricEncryptionStringHash,
											symmetricKey,
										},
									];
								})()
							: await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: suspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList:
												publishedList.metadata.encoding === 'base64url'
													? bitstring
													: toString(
															fromString(bitstring, 'base64url'),
															options!.publishOptions
																.statusListEncoding as DefaultStatusListEncoding
														),
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											encrypted: false,
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										undefined,
									];
								})();

						// early exit, if publish failed
						if (!scoped[0])
							throw new Error('[did-provider-cheqd]: suspension: Failed to publish status list 2021');

						// return publish result
						return scoped;
					})()
				: undefined;

			return {
				suspended: suspended.map((result) => (result.status === 'fulfilled' ? result.value.suspended : false)),
				published: topArgs?.publish ? true : undefined,
				statusList: topArgs?.returnUpdatedStatusList
					? ((await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Suspension)
					: undefined,
				symmetricKey: topArgs?.returnSymmetricKey
					? toString((published?.[1] as { symmetricKey: Uint8Array })?.symmetricKey, 'hex')
					: undefined,
				resourceMetadata: topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credentials[0])
					: undefined,
			} satisfies BulkSuspensionResult;
		} catch (error) {
			// silent fail + early exit
			console.error(error);
			return { suspended: [], error: error as IError } satisfies BulkSuspensionResult;
		}
	}

	static async unsuspendCredential(
		credential: VerifiableCredential,
		options?: ICheqdStatusListOptions
	): Promise<UnsuspensionResult> {
		try {
			// validate status purpose
			if (credential?.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension)
				throw new Error('[did-provider-cheqd]: unsuspension: Invalid status purpose');

			// fetch status list 2021
			const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension;

			// early return, if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey)
				throw new Error(
					'[did-provider-cheqd]: unsuspension: symmetricKey is required, if status list 2021 is encrypted'
				);

			// fetch status list 2021 inscribed in credential
			const statusList2021 = options?.topArgs?.fetchList
				? await (async function () {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted)
							return publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// decrypt + return bitstring, if qualified for migration
						if ((publishedList as StatusList2021SuspensionNonMigrated).metadata.encryptedSymmetricKey)
							return await LitProtocolV2.decryptDirect(
								await toBlob(
									fromString(
										(publishedList as StatusList2021SuspensionNonMigrated).StatusList2021
											.encodedList,
										'hex'
									)
								),
								fromString(options?.topArgs?.symmetricKey, 'hex')
							);

						// validate encoded list
						if (!isEncodedList(publishedList.StatusList2021.encodedList))
							throw new Error('[did-provider-cheqd]: unsuspension: Invalid encoded list');

						// otherwise, decrypt and return raw bitstring
						const scopedRawBlob = await toBlob(
							fromString(getEncodedList(publishedList.StatusList2021.encodedList, false)[0], 'hex')
						);

						// decrypt
						return toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);
					})()
				: await (async function () {
						// transcode to base64url, if needed
						const publishedListTranscoded =
							publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// if status list 2021 is not fetched, read from file
						if (options?.statusListFile) {
							// if not encrypted, return bitstring
							if (!publishedList.metadata.encrypted) {
								// construct encoded status list
								const encoded = new StatusList({
									buffer: await Cheqd.getFile(options.statusListFile),
								}).encode() as Bitstring;

								// validate against published list
								if (encoded !== publishedListTranscoded)
									throw new Error(
										'[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021'
									);

								// return encoded
								return encoded;
							}

							// otherwise, decrypt and return bitstring
							const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

							// decrypt
							const decrypted = toString(
								await LitProtocol.decryptDirect(
									scopedRawBlob,
									await safeDeserialise(
										options?.topArgs?.symmetricKey,
										fromString,
										['hex'],
										'Invalid symmetric key'
									)
								),
								'base64url'
							);

							// validate against published list
							if (decrypted !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021'
								);

							// return decrypted
							return decrypted;
						}

						if (!options?.statusListInlineBitstring)
							throw new Error(
								'[did-provider-cheqd]: unsuspension: statusListInlineBitstring is required, if statusListFile is not provided'
							);

						// validate against published list
						if (options?.statusListInlineBitstring !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: unsuspension: statusListInlineBitstring does not match published status list 2021'
							);

						// otherwise, read from inline bitstring
						return options?.statusListInlineBitstring;
					})();

			// parse status list 2021
			const statusList = await StatusList.decode({ encodedList: statusList2021 });

			// early exit, if already unsuspended
			if (!statusList.getStatus(Number(credential.credentialStatus.statusListIndex)))
				return { unsuspended: true } satisfies UnsuspensionResult;

			// update suspension status
			statusList.setStatus(Number(credential.credentialStatus.statusListIndex), false);

			// set in-memory status list ref
			const bitstring = (await statusList.encode()) as Bitstring;

			// cast top-level args
			const topArgs = options?.topArgs as ICheqdSuspendCredentialWithStatusListArgs;

			// write status list 2021 to file, if provided
			if (topArgs?.writeToFile) {
				await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile);
			}

			// publish status list 2021, if provided
			const published = topArgs?.publish
				? await (async function () {
						// fetch status list 2021 metadata
						const statusListMetadata = await Cheqd.fetchStatusListMetadata(credential);

						// publish status list 2021 as new version
						const scoped = topArgs.publishEncrypted
							? await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: unsuspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// validate paymentConditions, if provided
									if (topArgs?.paymentConditions) {
										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.feePaymentAddress &&
													condition.feePaymentAmount &&
													condition.intervalInSeconds
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													typeof condition.feePaymentAddress === 'string' &&
													typeof condition.feePaymentAmount === 'string' &&
													typeof condition.intervalInSeconds === 'number'
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.type === AccessControlConditionTypes.timelockPayment
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must be of type timelockPayment'
											);
										}
									}

									// validate dkgOptions
									if (
										!topArgs?.dkgOptions ||
										!topArgs?.dkgOptions?.chain ||
										!topArgs?.dkgOptions?.network
									) {
										throw new Error('[did-provider-cheqd]: dkgOptions is required');
									}

									// encrypt bitstring - case: symmetric
									const {
										encryptedString: symmetricEncryptionCiphertext,
										stringHash: symmetricEncryptionStringHash,
										symmetricKey,
									} = await LitProtocol.encryptDirect(fromString(bitstring, 'base64url'));

									// instantiate dkg-threshold client, in which case lit-protocol is used
									const lit = (await options!.publishOptions.instantiateDkgClient) as LitProtocol;

									// construct access control conditions and payment conditions tuple
									const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
										? await (async function () {
												// define payment conditions, give precedence to top-level args
												const paymentConditions =
													topArgs?.paymentConditions ||
													publishedList.metadata.paymentConditions!;

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight,
																		topArgs?.dkgOptions?.chain
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})()
										: await (async function () {
												// validate paymentConditions
												if (!topArgs?.paymentConditions) {
													throw new Error(
														'[did-provider-cheqd]: paymentConditions is required'
													);
												}

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														topArgs.paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													topArgs.paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})();

									// encrypt bitstring - case: threshold
									const {
										encryptedString: thresholdEncryptionCiphertext,
										stringHash: thresholdEncryptionStringHash,
									} = await lit.encrypt(
										fromString(bitstring, 'base64url'),
										unifiedAccessControlConditionsTuple[0]
									);

									// construct encoded list
									const encodedList = `${await blobToHexString(
										symmetricEncryptionCiphertext
									)}-${toString(thresholdEncryptionCiphertext, 'hex')}`;

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList,
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encrypted: true,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											statusListHash:
												symmetricEncryptionStringHash === thresholdEncryptionStringHash
													? symmetricEncryptionStringHash
													: (function () {
															throw new Error(
																'[did-provider-cheqd]: unsuspension: symmetricEncryptionStringHash and thresholdEncryptionStringHash do not match'
															);
														})(),
											paymentConditions: unifiedAccessControlConditionsTuple[1],
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										{
											symmetricEncryptionCiphertext,
											thresholdEncryptionCiphertext,
											stringHash: symmetricEncryptionStringHash,
											symmetricKey,
										},
									];
								})()
							: await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: unsuspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList:
												publishedList.metadata.encoding === 'base64url'
													? bitstring
													: toString(
															fromString(bitstring, 'base64url'),
															options!.publishOptions
																.statusListEncoding as DefaultStatusListEncoding
														),
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											encrypted: false,
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										undefined,
									];
								})();

						// early exit, if publish failed
						if (!scoped[0])
							throw new Error('[did-provider-cheqd]: unsuspension: Failed to publish status list 2021');

						// return publish result
						return scoped;
					})()
				: undefined;

			return {
				unsuspended: true,
				published: topArgs?.publish ? true : undefined,
				statusList: topArgs?.returnUpdatedStatusList
					? ((await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension)
					: undefined,
				symmetricKey: topArgs?.returnSymmetricKey
					? toString((published?.[1] as { symmetricKey: Uint8Array })?.symmetricKey, 'hex')
					: undefined,
				resourceMetadata: topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credential)
					: undefined,
			} satisfies UnsuspensionResult;
		} catch (error) {
			// silent fail + early exit
			console.error(error);

			return { unsuspended: false, error: error as IError } satisfies UnsuspensionResult;
		}
	}

	static async unsuspendCredentials(
		credentials: VerifiableCredential[],
		options?: ICheqdStatusListOptions
	): Promise<BulkUnsuspensionResult> {
		// validate credentials - case: empty
		if (!credentials.length || credentials.length === 0)
			throw new Error('[did-provider-cheqd]: unsuspension: No credentials provided');

		// validate credentials - case: consistent issuer
		if (
			credentials
				.map((credential) => {
					return (credential.issuer as { id: string }).id
						? (credential.issuer as { id: string }).id
						: (credential.issuer as string);
				})
				.filter((value, _, self) => value && value !== self[0]).length > 0
		)
			throw new Error('[did-provider-cheqd]: unsuspension: Credentials must be issued by the same issuer');

		// validate credentials - case: status list index
		if (
			credentials
				.map((credential) => credential.credentialStatus!.statusListIndex)
				.filter((value, index, self) => self.indexOf(value) !== index).length > 0
		)
			throw new Error('[did-provider-cheqd]: unsuspension: Credentials must have unique status list index');

		// validate credentials - case: status purpose
		if (
			!credentials.every(
				(credential) =>
					credential.credentialStatus?.statusPurpose === DefaultStatusList2021StatusPurposeTypes.suspension
			)
		)
			throw new Error('[did-provider-cheqd]: unsuspension: Invalid status purpose');

		// validate credentials - case: status list id
		const remote = credentials[0].credentialStatus?.id
			? (credentials[0].credentialStatus as { id: string }).id.split('#')[0]
			: (function () {
					throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list id');
				})();

		// validate credentials - case: status list id format
		if (!RemoteListPattern.test(remote))
			throw new Error(
				'[did-provider-cheqd]: unsuspension: Invalid status list id format: expected: https://<optional_subdomain>.<sld>.<tld>/1.0/identifiers/<did:cheqd:<namespace>:<method_specific_id>>?resourceName=<resource_name>&resourceType=<resource_type>'
			);

		if (
			!credentials.every((credential) => {
				return (credential.credentialStatus as { id: string }).id.split('#')[0] === remote;
			})
		)
			throw new Error('[did-provider-cheqd]: unsuspension: Credentials must belong to the same status list');

		// validate credentials - case: status list type
		if (!credentials.every((credential) => credential.credentialStatus?.type === 'StatusList2021Entry'))
			throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list type');

		try {
			// fetch status list 2021
			const publishedList = (await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Suspension;

			// early return, if encrypted and no decryption key provided
			if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey)
				throw new Error(
					'[did-provider-cheqd]: unsuspension: symmetricKey is required, if status list 2021 is encrypted'
				);

			// fetch status list 2021 inscribed in credential
			const statusList2021 = options?.topArgs?.fetchList
				? await (async function () {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted)
							return publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// decrypt + return bitstring, if qualified for migration
						if ((publishedList as StatusList2021SuspensionNonMigrated).metadata.encryptedSymmetricKey)
							return await LitProtocolV2.decryptDirect(
								await toBlob(
									fromString(
										(publishedList as StatusList2021SuspensionNonMigrated).StatusList2021
											.encodedList,
										'hex'
									)
								),
								fromString(options?.topArgs?.symmetricKey, 'hex')
							);

						// validate encoded list
						if (!isEncodedList(publishedList.StatusList2021.encodedList))
							throw new Error('[did-provider-cheqd]: unsuspension: Invalid encoded list');

						// otherwise, decrypt and return raw bitstring
						const scopedRawBlob = await toBlob(
							fromString(getEncodedList(publishedList.StatusList2021.encodedList, false)[0], 'hex')
						);

						// decrypt
						return toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);
					})()
				: await (async function () {
						// transcode to base64url, if needed
						const publishedListTranscoded =
							publishedList.metadata.encoding === 'base64url'
								? publishedList.StatusList2021.encodedList
								: toString(
										fromString(
											publishedList.StatusList2021.encodedList,
											publishedList.metadata.encoding as DefaultStatusListEncoding
										),
										'base64url'
									);

						// if status list 2021 is not fetched, read from file
						if (options?.statusListFile) {
							// if not encrypted, return bitstring
							if (!publishedList.metadata.encrypted) {
								// construct encoded status list
								const encoded = new StatusList({
									buffer: await Cheqd.getFile(options.statusListFile),
								}).encode() as Bitstring;

								// validate against published list
								if (encoded !== publishedListTranscoded)
									throw new Error(
										'[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021'
									);

								// return encoded
								return encoded;
							}

							// otherwise, decrypt and return bitstring
							const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

							// decrypt
							const decrypted = toString(
								await LitProtocol.decryptDirect(
									scopedRawBlob,
									await safeDeserialise(
										options?.topArgs?.symmetricKey,
										fromString,
										['hex'],
										'Invalid symmetric key'
									)
								),
								'base64url'
							);

							// validate against published list
							if (decrypted !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021'
								);

							// return decrypted
							return decrypted;
						}

						if (!options?.statusListInlineBitstring)
							throw new Error(
								'[did-provider-cheqd]: unsuspension: statusListInlineBitstring is required, if statusListFile is not provided'
							);

						// validate against published list
						if (options?.statusListInlineBitstring !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: unsuspension: statusListInlineBitstring does not match published status list 2021'
							);

						// otherwise, read from inline bitstring
						return options?.statusListInlineBitstring;
					})();

			// parse status list 2021
			const statusList = await StatusList.decode({ encodedList: statusList2021 });

			// initiate bulk unsuspension
			const unsuspended = (await Promise.allSettled(
				credentials.map((credential) => {
					return (async function () {
						// early return, if no credential status
						if (!credential.credentialStatus) return { unsuspended: false };

						// early exit, if credential is already unsuspended
						if (!statusList.getStatus(Number(credential.credentialStatus.statusListIndex)))
							return { unsuspended: true };

						// update unsuspension status
						statusList.setStatus(Number(credential.credentialStatus.statusListIndex), false);

						// return unsuspension status
						return { unsuspended: true };
					})();
				})
			)) satisfies PromiseSettledResult<UnsuspensionResult>[];

			// revert bulk ops, if some failed
			if (unsuspended.some((result) => result.status === 'fulfilled' && !result.value.unsuspended))
				throw new Error(
					`[did-provider-cheqd]: unsuspension: Bulk unsuspension failed: already unsuspended credentials in unsuspension bundle: raw log: ${JSON.stringify(
						unsuspended.map((result) => ({
							unsuspended: result.status === 'fulfilled' ? result.value.unsuspended : false,
						}))
					)}`
				);

			// set in-memory status list ref
			const bitstring = (await statusList.encode()) as Bitstring;

			// cast top-level args
			const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusListArgs;

			// write status list 2021 to file, if provided
			if (topArgs?.writeToFile) {
				await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile);
			}

			// publish status list 2021, if provided
			const published = topArgs?.publish
				? await (async function () {
						// fetch status list 2021 metadata
						const statusListMetadata = await Cheqd.fetchStatusListMetadata(credentials[0]);

						// publish status list 2021 as new version
						const scoped = topArgs.publishEncrypted
							? await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: unsuspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// validate paymentConditions, if provided
									if (topArgs?.paymentConditions) {
										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.feePaymentAddress &&
													condition.feePaymentAmount &&
													condition.intervalInSeconds
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													typeof condition.feePaymentAddress === 'string' &&
													typeof condition.feePaymentAmount === 'string' &&
													typeof condition.intervalInSeconds === 'number'
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number'
											);
										}

										if (
											!topArgs?.paymentConditions?.every(
												(condition) =>
													condition.type === AccessControlConditionTypes.timelockPayment
											)
										) {
											throw new Error(
												'[did-provider-cheqd]: paymentConditions must be of type timelockPayment'
											);
										}
									}

									// validate dkgOptions
									if (
										!topArgs?.dkgOptions ||
										!topArgs?.dkgOptions?.chain ||
										!topArgs?.dkgOptions?.network
									) {
										throw new Error('[did-provider-cheqd]: dkgOptions is required');
									}

									// encrypt bitstring - case: symmetric
									const {
										encryptedString: symmetricEncryptionCiphertext,
										stringHash: symmetricEncryptionStringHash,
										symmetricKey,
									} = await LitProtocol.encryptDirect(fromString(bitstring, 'base64url'));

									// instantiate dkg-threshold client, in which case lit-protocol is used
									const lit = (await options!.publishOptions.instantiateDkgClient) as LitProtocol;

									// construct access control conditions and payment conditions tuple
									const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
										? await (async function () {
												// define payment conditions, give precedence to top-level args
												const paymentConditions =
													topArgs?.paymentConditions ||
													publishedList.metadata.paymentConditions!;

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight,
																		topArgs?.dkgOptions?.chain
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})()
										: await (async function () {
												// validate paymentConditions
												if (!topArgs?.paymentConditions) {
													throw new Error(
														'[did-provider-cheqd]: paymentConditions is required'
													);
												}

												// return access control conditions and payment conditions tuple
												return [
													await Promise.all(
														topArgs.paymentConditions.map(async (condition) => {
															switch (condition.type) {
																case AccessControlConditionTypes.timelockPayment:
																	return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
																		{
																			key: '$.tx_responses.*.timestamp',
																			comparator: '<=',
																			value: `${condition.intervalInSeconds}`,
																		},
																		condition.feePaymentAmount,
																		condition.feePaymentAddress,
																		condition?.blockHeight
																	);
																default:
																	throw new Error(
																		`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
																	);
															}
														})
													),
													topArgs.paymentConditions,
												] satisfies [CosmosAccessControlCondition[], PaymentCondition[]];
											})();

									// encrypt bitstring - case: threshold
									const {
										encryptedString: thresholdEncryptionCiphertext,
										stringHash: thresholdEncryptionStringHash,
									} = await lit.encrypt(
										fromString(bitstring, 'base64url'),
										unifiedAccessControlConditionsTuple[0]
									);

									// construct encoded list
									const encodedList = `${await blobToHexString(
										symmetricEncryptionCiphertext
									)}-${toString(thresholdEncryptionCiphertext, 'hex')}`;

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList,
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encrypted: true,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											statusListHash:
												symmetricEncryptionStringHash === thresholdEncryptionStringHash
													? symmetricEncryptionStringHash
													: (function () {
															throw new Error(
																'[did-provider-cheqd]: unsuspension: symmetricEncryptionStringHash and thresholdEncryptionStringHash do not match'
															);
														})(),
											paymentConditions: unifiedAccessControlConditionsTuple[1],
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										{
											symmetricEncryptionCiphertext,
											thresholdEncryptionCiphertext,
											stringHash: symmetricEncryptionStringHash,
											symmetricKey,
										},
									];
								})()
							: await (async function () {
									// validate encoding, if provided
									if (
										options?.publishOptions?.statusListEncoding &&
										!Object.values(DefaultStatusListEncodings).includes(
											options?.publishOptions?.statusListEncoding
										)
									) {
										throw new Error(
											'[did-provider-cheqd]: unsuspension: Invalid status list encoding'
										);
									}

									// validate validUntil, if provided
									if (options?.publishOptions?.statusListValidUntil) {
										// validate validUntil as string
										if (typeof options?.publishOptions?.statusListValidUntil !== 'string')
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)'
											);

										// validate validUntil as date
										if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil)))
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)'
											);

										// validate validUntil as future date
										if (new Date(options?.publishOptions?.statusListValidUntil) < new Date())
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)'
											);

										// validate validUntil towards validFrom
										if (
											new Date(options?.publishOptions?.statusListValidUntil) <=
											new Date(publishedList.StatusList2021.validFrom)
										)
											throw new Error(
												'[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)'
											);
									}

									// define status list content
									const content = {
										StatusList2021: {
											statusPurpose: publishedList.StatusList2021.statusPurpose,
											encodedList:
												publishedList.metadata.encoding === 'base64url'
													? bitstring
													: toString(
															fromString(bitstring, 'base64url'),
															options!.publishOptions
																.statusListEncoding as DefaultStatusListEncoding
														),
											validFrom: publishedList.StatusList2021.validFrom,
											validUntil:
												options?.publishOptions?.statusListValidUntil ||
												publishedList.StatusList2021.validUntil,
										},
										metadata: {
											type: publishedList.metadata.type,
											encoding:
												(options?.publishOptions?.statusListEncoding as
													| DefaultStatusListEncoding
													| undefined) || publishedList.metadata.encoding,
											encrypted: false,
										},
									} satisfies StatusList2021Suspension;

									// return tuple of publish result and encryption relevant metadata
									return [
										await Cheqd.publishStatusList2021(
											fromString(JSON.stringify(content), 'utf-8'),
											statusListMetadata,
											options?.publishOptions
										),
										undefined,
									];
								})();

						// early exit, if publish failed
						if (!scoped[0])
							throw new Error('[did-provider-cheqd]: unsuspension: Failed to publish status list 2021');

						// return publish result
						return scoped;
					})()
				: undefined;

			return {
				unsuspended: unsuspended.map((result) =>
					result.status === 'fulfilled' ? result.value.unsuspended : false
				),
				published: topArgs?.publish ? true : undefined,
				statusList: topArgs?.returnUpdatedStatusList
					? ((await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Suspension)
					: undefined,
				symmetricKey: topArgs?.returnSymmetricKey
					? toString((published?.[1] as { symmetricKey: Uint8Array })?.symmetricKey, 'hex')
					: undefined,
				resourceMetadata: topArgs?.returnStatusListMetadata
					? await Cheqd.fetchStatusListMetadata(credentials[0])
					: undefined,
			} satisfies BulkUnsuspensionResult;
		} catch (error) {
			// silent fail + early exit
			console.error(error);

			return { unsuspended: [], error: error as IError } satisfies BulkUnsuspensionResult;
		}
	}

	static async checkRevoked(
		credential: VerifiableCredential,
		options: ICheqdStatusListOptions = { fetchList: true }
	): Promise<boolean> {
		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.revocation) {
			throw new Error(
				`[did-provider-cheqd]: check: revocation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// validate dkgOptions
		if (!options?.topArgs?.dkgOptions) {
			throw new Error('[did-provider-cheqd]: dkgOptions is required');
		}

		// fetch status list 2021
		const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Revocation;

		// route to non-migrated action, if applicable
		if ((publishedList as StatusList2021RevocationNonMigrated).metadata.encryptedSymmetricKey)
			return await this.checkRevokedNonMigrated(
				credential,
				publishedList as StatusList2021RevocationNonMigrated,
				options
			);

		// fetch status list 2021 inscribed in credential
		const statusList2021 = options?.topArgs?.fetchList
			? await (async function () {
					// if not encrypted, return bitstring
					if (!publishedList.metadata.encrypted)
						return publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// validate encoded list
					if (!isEncodedList(publishedList.StatusList2021.encodedList))
						throw new Error('[did-provider-cheqd]: check: revocation: Invalid encoded list');

					// otherwise, decrypt and return raw bitstring
					const thresholdEncryptionCiphertext = getEncodedList(
						publishedList.StatusList2021.encodedList,
						false
					)[1];

					// instantiate dkg-threshold client, in which case lit-protocol is used
					const lit = (await options.instantiateDkgClient) as LitProtocol;

					// construct access control conditions
					const unifiedAccessControlConditions = await Promise.all(
						publishedList.metadata.paymentConditions!.map(async (condition) => {
							switch (condition.type) {
								case AccessControlConditionTypes.timelockPayment:
									return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
										{
											key: '$.tx_responses.*.timestamp',
											comparator: '<=',
											value: `${condition.intervalInSeconds}`,
										},
										condition.feePaymentAmount,
										condition.feePaymentAddress,
										condition?.blockHeight,
										options?.topArgs?.dkgOptions?.chain
									);
								default:
									throw new Error(
										`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
									);
							}
						})
					);

					// decrypt
					return await lit.decrypt(
						thresholdEncryptionCiphertext,
						publishedList.metadata.statusListHash!,
						unifiedAccessControlConditions,
						options?.topArgs?.dkgOptions?.capacityDelegationAuthSignature
					);
				})()
			: await (async function () {
					// transcode to base64url, if needed
					const publishedListTranscoded =
						publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// if status list 2021 is not fetched, read from file
					if (options?.statusListFile) {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted) {
							// construct encoded status list
							const encoded = new StatusList({
								buffer: await Cheqd.getFile(options.statusListFile),
							}).encode() as Bitstring;

							// validate against published list
							if (encoded !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: check: revocation: statusListFile does not match published status list 2021'
								);

							// return encoded
							return encoded;
						}

						// otherwise, decrypt and return bitstring
						const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

						// decrypt
						const decrypted = toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);

						// validate against published list
						if (decrypted !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: check: revocation: statusListFile does not match published status list 2021'
							);

						// return decrypted
						return decrypted;
					}

					if (!options?.statusListInlineBitstring)
						throw new Error(
							'[did-provider-cheqd]: check: revocation: statusListInlineBitstring is required, if statusListFile is not provided'
						);

					// validate against published list
					if (options?.statusListInlineBitstring !== publishedListTranscoded)
						throw new Error(
							'[did-provider-cheqd]: check: revocation: statusListInlineBitstring does not match published status list 2021'
						);

					// otherwise, read from inline bitstring
					return options?.statusListInlineBitstring;
				})();

		// transcode, if needed
		const transcodedStatusList2021 =
			publishedList.metadata.encoding === 'base64url'
				? statusList2021
				: toString(
						fromString(statusList2021, publishedList.metadata.encoding as DefaultStatusListEncoding),
						'base64url'
					);

		// parse status list 2021
		const statusList = await StatusList.decode({ encodedList: transcodedStatusList2021 });

		// get status by index
		return !!statusList.getStatus(Number(credential.credentialStatus.statusListIndex));
	}

	static async checkSuspended(
		credential: VerifiableCredential,
		options: ICheqdStatusListOptions = { fetchList: true }
	): Promise<boolean> {
		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension) {
			throw new Error(
				`[did-provider-cheqd]: check: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// validate dkgOptions
		if (!options?.topArgs?.dkgOptions) {
			throw new Error('[did-provider-cheqd]: dkgOptions is required');
		}

		// fetch status list 2021
		const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension;

		// route to non-migrated action, if applicable
		if ((publishedList as StatusList2021SuspensionNonMigrated).metadata.encryptedSymmetricKey)
			return await this.checkSuspendedNonMigrated(
				credential,
				publishedList as StatusList2021SuspensionNonMigrated,
				options
			);

		// fetch status list 2021 inscribed in credential
		const statusList2021 = options?.topArgs?.fetchList
			? await (async function () {
					// if not encrypted, return bitstring
					if (!publishedList.metadata.encrypted)
						return publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// otherwise, decrypt and return bitstring
					const thresholdEncryptionCiphertext = getEncodedList(
						publishedList.StatusList2021.encodedList,
						false
					)[1];

					// instantiate dkg-threshold client, in which case lit-protocol is used
					const lit = (await options.instantiateDkgClient) as LitProtocol;

					// construct access control conditions
					const unifiedAccessControlConditions = await Promise.all(
						publishedList.metadata.paymentConditions!.map(async (condition) => {
							switch (condition.type) {
								case AccessControlConditionTypes.timelockPayment:
									return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
										{
											key: '$.tx_responses.*.timestamp',
											comparator: '<=',
											value: `${condition.intervalInSeconds}`,
										},
										condition.feePaymentAmount,
										condition.feePaymentAddress,
										condition?.blockHeight,
										options?.topArgs?.dkgOptions?.chain
									);
								default:
									throw new Error(
										`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
									);
							}
						})
					);

					// decrypt
					return await lit.decrypt(
						thresholdEncryptionCiphertext,
						publishedList.metadata.statusListHash!,
						unifiedAccessControlConditions,
						options?.topArgs?.dkgOptions?.capacityDelegationAuthSignature
					);
				})()
			: await (async function () {
					// transcode to base64url, if needed
					const publishedListTranscoded =
						publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// if status list 2021 is not fetched, read from file
					if (options?.statusListFile) {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted) {
							// construct encoded status list
							const encoded = new StatusList({
								buffer: await Cheqd.getFile(options.statusListFile),
							}).encode() as Bitstring;

							// validate against published list
							if (encoded !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: check: suspension: statusListFile does not match published status list 2021'
								);

							// return encoded
							return encoded;
						}

						// otherwise, decrypt and return bitstring
						const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

						// decrypt
						const decrypted = toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);

						// validate against published list
						if (decrypted !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: check: suspension: statusListFile does not match published status list 2021'
							);

						// return decrypted
						return decrypted;
					}

					if (!options?.statusListInlineBitstring)
						throw new Error(
							'[did-provider-cheqd]: check: suspension: statusListInlineBitstring is required, if statusListFile is not provided'
						);

					// validate against published list
					if (options?.statusListInlineBitstring !== publishedListTranscoded)
						throw new Error(
							'[did-provider-cheqd]: check: suspension: statusListInlineBitstring does not match published status list 2021'
						);

					// otherwise, read from inline bitstring
					return options?.statusListInlineBitstring;
				})();

		// parse status list 2021
		const statusList = await StatusList.decode({ encodedList: statusList2021 });

		// get status by index
		return !!statusList.getStatus(Number(credential.credentialStatus.statusListIndex));
	}

	private static async checkRevokedNonMigrated(
		credential: VerifiableCredential,
		associatedStatusList?: StatusList2021RevocationNonMigrated,
		options: ICheqdStatusListOptions = { fetchList: true }
	): Promise<boolean> {
		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.revocation) {
			throw new Error(
				`[did-provider-cheqd]: check: revocation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// fetch status list 2021
		const publishedList =
			associatedStatusList ||
			((await Cheqd.fetchStatusList2021(credential)) as StatusList2021RevocationNonMigrated);

		// validate migrated
		if (!publishedList.metadata.encryptedSymmetricKey)
			throw new Error('[did-provider-cheqd]: check: revocation: Invalid migrated status list');

		// fetch status list 2021 inscribed in credential
		const statusList2021 = options?.topArgs?.fetchList
			? await (async function () {
					// if not encrypted, return bitstring
					if (!publishedList.metadata.encrypted)
						return publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// otherwise, decrypt and return raw bitstring
					const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'));

					// instantiate dkg-threshold client, in which case lit-protocol is used
					const lit = await LitProtocolV2.create({
						chain: options?.topArgs?.dkgOptions?.chain,
						litNetwork: LitNetworksV2.serrano,
					});

					// construct access control conditions
					const unifiedAccessControlConditions = await Promise.all(
						publishedList.metadata.paymentConditions!.map(async (condition) => {
							switch (condition.type) {
								case AccessControlConditionTypes.timelockPayment:
									return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
										{
											key: '$.tx_responses.*.timestamp',
											comparator: '<=',
											value: `${condition.intervalInSeconds}`,
										},
										condition.feePaymentAmount,
										condition.feePaymentAddress,
										condition?.blockHeight,
										options?.topArgs?.dkgOptions?.chain
									);
								default:
									throw new Error(
										`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
									);
							}
						})
					);

					// decrypt
					return await lit.decrypt(
						scopedRawBlob,
						publishedList.metadata.encryptedSymmetricKey!,
						unifiedAccessControlConditions
					);
				})()
			: await (async function () {
					// transcode to base64url, if needed
					const publishedListTranscoded =
						publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// if status list 2021 is not fetched, read from file
					if (options?.statusListFile) {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted) {
							// construct encoded status list
							const encoded = new StatusList({
								buffer: await Cheqd.getFile(options.statusListFile),
							}).encode() as Bitstring;

							// validate against published list
							if (encoded !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: check: revocation: statusListFile does not match published status list 2021'
								);

							// return encoded
							return encoded;
						}

						// otherwise, decrypt and return bitstring
						const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

						// decrypt
						const decrypted = await LitProtocolV2.decryptDirect(
							scopedRawBlob,
							fromString(options?.topArgs?.symmetricKey, 'hex')
						);

						// validate against published list
						if (decrypted !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: check: revocation: statusListFile does not match published status list 2021'
							);

						// return decrypted
						return decrypted;
					}

					if (!options?.statusListInlineBitstring)
						throw new Error(
							'[did-provider-cheqd]: check: revocation: statusListInlineBitstring is required, if statusListFile is not provided'
						);

					// validate against published list
					if (options?.statusListInlineBitstring !== publishedListTranscoded)
						throw new Error(
							'[did-provider-cheqd]: check: revocation: statusListInlineBitstring does not match published status list 2021'
						);

					// otherwise, read from inline bitstring
					return options?.statusListInlineBitstring;
				})();

		// transcode, if needed
		const transcodedStatusList2021 =
			publishedList.metadata.encoding === 'base64url'
				? statusList2021
				: toString(
						fromString(statusList2021, publishedList.metadata.encoding as DefaultStatusListEncoding),
						'base64url'
					);

		// parse status list 2021
		const statusList = await StatusList.decode({ encodedList: transcodedStatusList2021 });

		// get status by index
		return !!statusList.getStatus(Number(credential.credentialStatus.statusListIndex));
	}

	private static async checkSuspendedNonMigrated(
		credential: VerifiableCredential,
		associatedStatusList?: StatusList2021SuspensionNonMigrated,
		options: ICheqdStatusListOptions = { fetchList: true }
	): Promise<boolean> {
		// validate status purpose
		if (credential.credentialStatus?.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension) {
			throw new Error(
				`[did-provider-cheqd]: check: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`
			);
		}

		// fetch status list 2021
		const publishedList =
			associatedStatusList ||
			((await Cheqd.fetchStatusList2021(credential)) as StatusList2021SuspensionNonMigrated);

		// validate migrated
		if (!publishedList.metadata.encryptedSymmetricKey)
			throw new Error('[did-provider-cheqd]: check: suspension: Invalid migrated status list');

		// fetch status list 2021 inscribed in credential
		const statusList2021 = options?.topArgs?.fetchList
			? await (async function () {
					// if not encrypted, return bitstring
					if (!publishedList.metadata.encrypted)
						return publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// otherwise, decrypt and return raw bitstring
					const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'));

					// instantiate dkg-threshold client, in which case lit-protocol is used
					const lit = await LitProtocolV2.create({
						chain: options?.topArgs?.dkgOptions?.chain,
						litNetwork: LitNetworksV2.serrano,
					});

					// construct access control conditions
					const unifiedAccessControlConditions = await Promise.all(
						publishedList.metadata.paymentConditions!.map(async (condition) => {
							switch (condition.type) {
								case AccessControlConditionTypes.timelockPayment:
									return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock(
										{
											key: '$.tx_responses.*.timestamp',
											comparator: '<=',
											value: `${condition.intervalInSeconds}`,
										},
										condition.feePaymentAmount,
										condition.feePaymentAddress,
										condition?.blockHeight,
										options?.topArgs?.dkgOptions?.chain
									);
								default:
									throw new Error(
										`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`
									);
							}
						})
					);

					// decrypt
					return await lit.decrypt(
						scopedRawBlob,
						publishedList.metadata.encryptedSymmetricKey!,
						unifiedAccessControlConditions
					);
				})()
			: await (async function () {
					// transcode to base64url, if needed
					const publishedListTranscoded =
						publishedList.metadata.encoding === 'base64url'
							? publishedList.StatusList2021.encodedList
							: toString(
									fromString(
										publishedList.StatusList2021.encodedList,
										publishedList.metadata.encoding as DefaultStatusListEncoding
									),
									'base64url'
								);

					// if status list 2021 is not fetched, read from file
					if (options?.statusListFile) {
						// if not encrypted, return bitstring
						if (!publishedList.metadata.encrypted) {
							// construct encoded status list
							const encoded = new StatusList({
								buffer: await Cheqd.getFile(options.statusListFile),
							}).encode() as Bitstring;

							// validate against published list
							if (encoded !== publishedListTranscoded)
								throw new Error(
									'[did-provider-cheqd]: check: suspension: statusListFile does not match published status list 2021'
								);

							// return encoded
							return encoded;
						}

						// otherwise, decrypt and return bitstring
						const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile));

						// decrypt
						const decrypted = toString(
							await LitProtocol.decryptDirect(
								scopedRawBlob,
								await safeDeserialise(
									options?.topArgs?.symmetricKey,
									fromString,
									['hex'],
									'Invalid symmetric key'
								)
							),
							'base64url'
						);

						// validate against published list
						if (decrypted !== publishedListTranscoded)
							throw new Error(
								'[did-provider-cheqd]: check: suspension: statusListFile does not match published status list 2021'
							);

						// return decrypted
						return decrypted;
					}

					if (!options?.statusListInlineBitstring)
						throw new Error(
							'[did-provider-cheqd]: check: suspension: statusListInlineBitstring is required, if statusListFile is not provided'
						);

					// validate against published list
					if (options?.statusListInlineBitstring !== publishedListTranscoded)
						throw new Error(
							'[did-provider-cheqd]: check: suspension: statusListInlineBitstring does not match published status list 2021'
						);

					// otherwise, read from inline bitstring
					return options?.statusListInlineBitstring;
				})();

		// parse status list 2021
		const statusList = await StatusList.decode({ encodedList: statusList2021 });

		// get status by index
		return !!statusList.getStatus(Number(credential.credentialStatus.statusListIndex));
	}

	static async publishStatusList2021(
		statusList2021Raw: Uint8Array,
		statusList2021Metadata: LinkedResourceMetadataResolutionResult,
		options: {
			context: IContext;
			resourceId?: string;
			resourceVersion?: string;
			resourceAlsoKnownAs?: AlternativeUri[];
			signInputs?: ISignInputs[];
			fee?: DidStdFee | 'auto' | number;
		}
	): Promise<boolean> {
		// construct status list 2021 payload from previous version + new version
		const payload = {
			collectionId: statusList2021Metadata.resourceCollectionId,
			id: options?.resourceId || v4(),
			name: statusList2021Metadata.resourceName,
			version: options?.resourceVersion || new Date().toISOString(),
			alsoKnownAs: options?.resourceAlsoKnownAs || [],
			resourceType: statusList2021Metadata.resourceType as DefaultStatusList2021ResourceType,
			data: statusList2021Raw,
		} satisfies StatusList2021ResourcePayload;

		return await options.context.agent[BroadcastStatusList2021MethodName]({
			kms: (await options.context.agent.keyManagerGetKeyManagementSystems())[0],
			payload,
			network: statusList2021Metadata.resourceURI.split(':')[2] as CheqdNetwork,
			signInputs: options?.signInputs,
			fee: options?.fee,
		});
	}

	static async fetchStatusList2021(
		credential: VerifiableCredential,
		returnRaw = false
	): Promise<StatusList2021Revocation | StatusList2021Suspension | Uint8Array> {
		// validate credential status
		if (!credential.credentialStatus)
			throw new Error('[did-provider-cheqd]: fetch status list: Credential status is not present');

		// validate credential status type
		if (credential.credentialStatus.type !== 'StatusList2021Entry')
			throw new Error('[did-provider-cheqd]: fetch status list: Credential status type is not valid');

		// validate credential status list status purpose
		if (
			credential.credentialStatus.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.revocation &&
			credential.credentialStatus.statusPurpose !== DefaultStatusList2021StatusPurposeTypes.suspension
		)
			throw new Error('[did-provider-cheqd]: fetch status list: Credential status purpose is not valid');

		// fetch status list 2021
		const content = (await (await fetch(credential.credentialStatus.id.split('#')[0])).json()) as
			| StatusList2021Revocation
			| StatusList2021Suspension;

		if (
			!(
				content.StatusList2021 &&
				content.metadata &&
				content.StatusList2021.encodedList &&
				content.StatusList2021.statusPurpose &&
				content.metadata.encoding
			)
		) {
			throw new Error(`'[did-provider-cheqd]: fetch status list: Status List resource content is not valid'`);
		}

		// return raw if requested
		if (returnRaw) {
			return fromString(
				content.StatusList2021.encodedList,
				content.metadata.encoding as DefaultStatusListEncoding
			);
		}

		// otherwise, return content
		return content;
	}

	static async fetchStatusListMetadata(
		credential: VerifiableCredential
	): Promise<LinkedResourceMetadataResolutionResult> {
		// get base url
		const baseUrl = new URL(credential.credentialStatus!.id.split('#')[0]);

		// get resource name
		const resourceName = baseUrl.searchParams.get('resourceName');

		// get resource type
		const resourceType = baseUrl.searchParams.get('resourceType');

		// unset resource name
		baseUrl.searchParams.delete('resourceName');

		// unset resource type
		baseUrl.searchParams.delete('resourceType');

		// construct metadata url
		const metadataUrl = `${baseUrl.toString()}/metadata`;

		// fetch collection metadata
		const didResolutionResult = (await (
			await fetch(metadataUrl, {
				headers: {
					Accept: 'application/ld+json;profile=https://w3id.org/did-resolution',
				},
			})
		).json()) as DIDResolutionResult;

		// early exit if no linked resources
		if (!didResolutionResult?.didDocumentMetadata?.linkedResourceMetadata)
			throw new Error('[did-provider-cheqd]: fetch status list metadata: No linked resources found');

		// find relevant resources by resource name
		const resourceVersioning = didResolutionResult.didDocumentMetadata.linkedResourceMetadata.filter(
			(resource) => resource.resourceName === resourceName && resource.resourceType === resourceType
		);

		// early exit if no relevant resources
		if (!resourceVersioning.length || resourceVersioning.length === 0)
			throw new Error(
				`[did-provider-cheqd]: fetch status list metadata: No relevant resources found by resource name ${resourceName}`
			);

		// get latest resource version by nextVersionId null pointer, or by latest created date as fallback
		return (
			resourceVersioning.find((resource) => !resource.nextVersionId) ||
			resourceVersioning.sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime())[0]
		);
	}
	/**
	 * Fetch the JSON metadata from a bitstring status list credential URL
	 */
	static async fetchBitstringStatusList(credential: VerifiableCredential): Promise<BitstringStatusList> {
		// get base url
		const baseUrl = new URL(credential.credentialStatus!.id.split('#')[0]);
		// fetch collection metadata
		const response = await fetch(baseUrl, {
			method: 'GET',
			headers: {
				Accept: 'application/json',
				'Content-Type': 'application/json',
			},
		});
		if (!response.ok) {
			throw new Error(
				`[did-provider-cheqd]: Bitstring Status List retrieval error ${response.status}: ${response.statusText}`
			);
		}
		const data: BitstringStatusList = await response.json();
		return data;
	}

	static async getProviderFromDidUrl(
		didUrl: string,
		providers: CheqdDIDProvider[],
		message?: string
	): Promise<CheqdDIDProvider> {
		const provider = providers.find((provider) =>
			didUrl.includes(`${DidPrefix}:${CheqdDidMethod}:${provider.network}:`)
		);
		if (!provider) {
			throw new Error(
				message ||
					`[did-provider-cheqd]: no relevant providers found for did url ${didUrl}: loaded providers: ${providers.map((provider) => `${DidPrefix}:${CheqdDidMethod}:${provider.network}`).join(', ')}`
			);
		}
		return provider;
	}

	static async getProviderFromNetwork(
		network: CheqdNetwork,
		providers: CheqdDIDProvider[],
		message?: string
	): Promise<CheqdDIDProvider> {
		const provider = providers.find((provider) => provider.network === network);
		if (!provider) {
			throw new Error(
				message ||
					`[did-provider-cheqd]: no relevant providers found for network ${network}: loaded providers: ${providers.map((provider) => `${DidPrefix}:${CheqdDidMethod}:${provider.network}`).join(', ')}`
			);
		}
		return provider;
	}

	static generateProviderId(namespace: string): string {
		return `${DidPrefix}:${CheqdDidMethod}:${namespace}`;
	}

	static async getFile(filename: string): Promise<Uint8Array> {
		if (typeof filename !== 'string') {
			throw new Error('[did-provider-cheqd]: filename is required');
		}

		if (!fs.existsSync(filename)) {
			debug(`[did-provider-cheqd]: File ${filename} not found`);
			throw new Error(`[did-provider-cheqd]: File ${filename} not found`);
		}

		return new Promise((resolve, reject) => {
			const content = fs.readFileSync(filename);
			if (!content) {
				reject(new Error(`[did-provider-cheqd]: File ${filename} is empty`));
			}
			resolve(new Uint8Array(content));
		});
	}

	static async writeFile(content: Uint8Array, filename?: string): Promise<void> {
		if (!filename) {
			filename = `statusList2021-${v4()}`;
		}

		// alert if file exists
		if (fs.existsSync(filename)) {
			debug(`[did-provider-cheqd]: File ${filename} already exists`);
			console.warn(`[did-provider-cheqd]: File ${filename} already exists. Overwriting...`);
		}

		return new Promise((resolve, reject) => {
			fs.writeFile(filename!, content, (err) => {
				if (err) {
					reject(new Error(`[did-provider-cheqd]: Error writing file ${filename}: reason: ${err}`));
				}
				resolve();
			});
		});
	}

	static async decodeCredentialJWT(jwt: string): Promise<VerifiableCredential> {
		const decodedCredential = decodeJWT(jwt);

		// validate credential payload
		if (!decodedCredential.payload)
			throw new Error('[did-provider-cheqd]: decode jwt: decodedCredential.payload is required');

		// validate credential payload vc property as VerifiableCredential
		if (!decodedCredential.payload.vc)
			throw new Error('[did-provider-cheqd]: decode jwt: decodedCredential.payload.vc is required');

		return {
			...decodedCredential.payload.vc,
			issuer: decodedCredential.payload.iss,
		} satisfies VerifiableCredential | BitstringStatusListCredential;
	}
	static getBitValue(bitstring: DBBitstring, bitIndex: number, statusSize = 1): number {
		let value = 0;
		for (let i = 0; i < statusSize; i++) {
			const bit = bitstring.get(bitIndex + i);
			value |= bit << i;
		}
		return value;
	}
	// Helper function to set bit values in a bitstring (2-bit values)
	static setBitValue(bitstring: DBBitstring, bitIndex: number, value: number, statusSize: number = 2): void {
		for (let i = 0; i < statusSize; i++) {
			const bit = (value >> i) & 1;
			bitstring.set(bitIndex + i, bit === 1);
		}
	}
}
export { BitstringStatusListResourceType, DefaultStatusListEncodings };
