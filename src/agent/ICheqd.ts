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
    VerificationMethods,
    createDidPayload,
    createDidVerificationMethod,
    createKeyPairBase64,
    createKeyPairHex,
    createVerificationKeys
} from '@cheqd/sdk'
import {
    Coin,
    DeliverTxResponse
} from '@cosmjs/stargate'
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
} from '@veramo/core'
import {
    CheqdDIDProvider,
    LinkedResource,
    TImportableEd25519Key,
    ResourcePayload,
    StatusList2021ResourcePayload,
    DefaultRESTUrls,
    DefaultStatusList2021Encodings,
    DefaultStatusList2021ResourceTypes,
    DefaultStatusList2021StatusPurposeTypes,
    DefaultStatusList2021Encoding,
    DefaultStatusList2021ResourceType,
    DefaultStatusList2021StatusPurposeType,
} from '../did-manager/cheqd-did-provider.js'
import {
    fromString,
    toString
} from 'uint8arrays'
import { decodeJWT } from 'did-jwt'
import { StatusList } from '@digitalbazaar/vc-status-list'
import { v4 } from 'uuid'
import fs from 'fs'
import Debug from 'debug'
import {
    CosmosAccessControlCondition,
    LitCompatibleCosmosChain,
    LitCompatibleCosmosChains,
    LitNetwork,
    LitProtocol,
} from '../dkg-threshold/lit-protocol.js';
import {
    blobToHexString,
    randomFromRange,
    toBlob,
} from '../utils/helpers.js'
import { DefaultResolverUrl } from '../did-manager/cheqd-did-resolver.js'
import { AlternativeUri } from '@cheqd/ts-proto/cheqd/resource/v2/resource.js'

const debug = Debug('veramo:did-provider-cheqd')

export type IContext = IAgentContext<IDIDManager & IKeyManager & IDataStore & IResolver & ICredentialIssuer & ICredentialVerifier & ICheqd>
export type TExportedDIDDocWithKeys = { didDoc: DIDDocument, keys: TImportableEd25519Key[], versionId?: string }
export type TExportedDIDDocWithLinkedResourceWithKeys = TExportedDIDDocWithKeys & { linkedResource: LinkedResource }
export type LinkedResourceMetadataResolutionResult = { resourceURI: string, resourceCollectionId: string, resourceId: string, resourceName: string, resourceType: string, mediaType: string, resourceVersion?: string, created: string, checksum: string, previousVersionId: string | null, nextVersionId: string | null }
export type DIDMetadataDereferencingResult = { '@context': 'https://w3id.org/did-resolution/v1', dereferencingMetadata: { contentType: string, retrieved: string, did: { didString: string, methodSpecificId: string, method: string } }, contentStream: { created: string, versionId: string, linkedResourceMetadata: LinkedResourceMetadataResolutionResult[] }, contentMetadata: Record<string, any> }
export type ShallowTypedTx = { body: { messages: any[], memo: string, timeout_height: string, extension_options: any[], non_critical_extension_options: any[] }, auth_info: { signer_infos: { public_key: { '@type': string, key: string }, mode_info: { single: { mode: string } }, sequence: string }[], fee: { amount: Coin[], gas_limit: string, payer: string, granter: string }, tip: any | null }, signatures: string[] }
export type ShallowTypedTxTxResponses = { height: string, txhash: string, codespace: string, code: number, data: string, raw_log: string, logs: any[], info: string, gas_wanted: string, gas_used: string, tx: ShallowTypedTx, timestamp: string, events: any[] }
export type ShallowTypedTxsResponse = { txs: ShallowTypedTx[], tx_responses: ShallowTypedTxTxResponses[], pagination: string | null, total: string } | undefined
export type BlockResponse = { block_id: BlockID, block: Block, sdk_block: Block}
export type Block = { header: Header, data: Data, evidence: Evidence, last_commit: LastCommit }
export type Data = { txs: any[] }
export type Evidence = { evidence: any[] }
export type Header = { version: Version, chain_id: string, height: string, time: string, last_block_id: BlockID, last_commit_hash: string, data_hash: string, validators_hash: string, next_validators_hash: string, consensus_hash: string, app_hash: string, last_results_hash: string, evidence_hash: string, proposer_address: string }
export type BlockID = { hash: string, part_set_header: PartSetHeader }
export type PartSetHeader = { total: number, hash: string }
export type Version = { block: string, app: string }
export type LastCommit = { height: string, round: number, block_id: BlockID, signatures: Signature[] }
export type Signature = { block_id_flag: string, validator_address?: string, timestamp: Date, signature?: string }
export type VerificationResult = { verified: boolean, revoked?: boolean, suspended?: boolean, error?: IVerifyResult['error'] }
export type StatusCheckResult = { revoked?: boolean, suspended?: boolean, error?: IError }
export type RevocationResult = { revoked: boolean, error?: IError, statusList?: StatusList2021Revocation, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type BulkRevocationResult = { revoked: boolean[], error?: IError, statusList?: StatusList2021Revocation, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type SuspensionResult = { suspended: boolean, error?: IError, statusList?: StatusList2021Suspension, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type BulkSuspensionResult = { suspended: boolean[], error?: IError, statusList?: StatusList2021Suspension, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type UnsuspensionResult = { unsuspended: boolean, error?: IError, statusList?: StatusList2021Suspension, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type BulkUnsuspensionResult = { unsuspended: boolean[], error?: IError, statusList?: StatusList2021Suspension, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type Bitstring = string
export type StatusList2021Revocation = { StatusList2021: { statusPurpose: typeof DefaultStatusList2021StatusPurposeTypes.revocation, encodedList: string, validFrom: string, validUntil?: string }, metadata: { type: typeof DefaultStatusList2021ResourceTypes.revocation, encrypted: boolean, encoding: DefaultStatusList2021Encoding, encryptedSymmetricKey?: string, paymentConditions?: PaymentCondition[] } }
export type StatusList2021Suspension = { StatusList2021: { statusPurpose: typeof DefaultStatusList2021StatusPurposeTypes.suspension, encodedList: string, validFrom: string, validUntil?: string }, metadata: { type: typeof DefaultStatusList2021ResourceTypes.suspension, encrypted: boolean, encoding: DefaultStatusList2021Encoding, encryptedSymmetricKey?: string, paymentConditions?: PaymentCondition[] } }
export type AccessControlConditionType = typeof AccessControlConditionTypes[keyof typeof AccessControlConditionTypes]
export type AccessControlConditionReturnValueComparator = typeof AccessControlConditionReturnValueComparators[keyof typeof AccessControlConditionReturnValueComparators]
export type PaymentCondition = { feePaymentAddress: string, feePaymentAmount: string, intervalInSeconds: number, blockHeight?: string, type: Extract<AccessControlConditionType, 'timelockPayment'> }
export type DkgOptions = { chain?: Extract<LitCompatibleCosmosChain, 'cheqdTestnet' | 'cheqdMainnet'>, network?: LitNetwork }
export type CreateStatusList2021Result = { created: boolean, error?: Error, resource: StatusList2021Revocation | StatusList2021Suspension, resourceMetadata: LinkedResourceMetadataResolutionResult, encrypted?: boolean, symmetricKey?: string }
export type TransactionResult = { successful: boolean, transactionHash?: string, events?: DeliverTxResponse['events'], rawLog?: string, txResponse?: DeliverTxResponse, error?: IError }
export type ObservationResult = { subscribed: boolean, meetsCondition: boolean, transactionHash?: string, events?: DeliverTxResponse['events'], rawLog?: string, txResponse?: ShallowTypedTxTxResponses, error?: IError }

export const AccessControlConditionTypes = { timelockPayment: 'timelockPayment', memoNonce: 'memoNonce', balance: 'balance' } as const
export const AccessControlConditionReturnValueComparators = { lessThan: '<', greaterThan: '>', equalTo: '=', lessThanOrEqualTo: '<=', greaterThanOrEqualTo: '>=' } as const

export const RemoteListPattern = /^(https:\/\/)?[a-z0-9_-]+(\.[a-z0-9_-]+)*\.[a-z]{2,}\/1\.0\/identifiers\/did:cheqd:[a-z]+:[a-zA-Z0-9-]+\?((resourceName=[^&]*)&(resourceType=[^&]*)|((resourceType=[^&]*)&(resourceName=[^&]*)))$/

export const CreateIdentifierMethodName = 'cheqdCreateIdentifier'
export const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier'
export const DeactivateIdentifierMethodName = 'cheqdDeactivateIdentifier'
export const CreateResourceMethodName = 'cheqdCreateLinkedResource'
export const CreateStatusList2021MethodName = 'cheqdCreateStatusList2021'
export const BroadcastStatusList2021MethodName = 'cheqdBroadcastStatusList2021'
export const GenerateDidDocMethodName = 'cheqdGenerateDidDoc'
export const GenerateDidDocWithLinkedResourceMethodName = 'cheqdGenerateDidDocWithLinkedResource'
export const GenerateKeyPairMethodName = 'cheqdGenerateIdentityKeys'
export const GenerateVersionIdMethodName = 'cheqdGenerateVersionId'
export const GenerateStatusList2021MethodName = 'cheqdGenerateStatusList2021'
export const IssueRevocableCredentialWithStatusList2021MethodName = 'cheqdIssueRevocableCredentialWithStatusList2021'
export const IssueSuspendableCredentialWithStatusList2021MethodName = 'cheqdIssueSuspendableCredentialWithStatusList2021'
export const VerifyCredentialMethodName = 'cheqdVerifyCredential'
export const VerifyPresentationMethodName = 'cheqdVerifyPresentation' 
export const CheckCredentialStatusMethodName = 'cheqdCheckCredentialStatus' 
export const RevokeCredentialMethodName = 'cheqdRevokeCredential'
export const RevokeCredentialsMethodName = 'cheqdRevokeCredentials'
export const SuspendCredentialMethodName = 'cheqdSuspendCredential'
export const SuspendCredentialsMethodName = 'cheqdSuspendCredentials'
export const UnsuspendCredentialMethodName = 'cheqdUnsuspendCredential'
export const UnsuspendCredentialsMethodName = 'cheqdUnsuspendCredentials'
export const TransactSendTokensMethodName = 'cheqdTransactSendTokens'
export const ObservePaymentConditionMethodName = 'cheqdObservePaymentCondition'

export const DidPrefix = 'did'
export const CheqdDidMethod = 'cheqd'

export interface ICheqdCreateIdentifierArgs {
    kms: string
    alias: string
    document: DIDDocument
    keys?: TImportableEd25519Key[]
    versionId?: string
    fee?: DidStdFee
}

export interface ICheqdUpdateIdentifierArgs {
    kms: string
    document: DIDDocument
    keys?: TImportableEd25519Key[]
    versionId?: string
    fee?: DidStdFee
}

export interface ICheqdDeactivateIdentifierArgs {
    kms: string
    document: DIDDocument
    keys?: TImportableEd25519Key[]
    fee?: DidStdFee
}

export interface ICheqdCreateLinkedResourceArgs {
    kms: string
    payload: ResourcePayload
    network: CheqdNetwork
    file?: string
    signInputs?: ISignInputs[]
    fee?: DidStdFee
}

export interface ICheqdCreateStatusList2021Args {
    kms: string
    issuerDid: string
    statusListName: string
    statusPurpose: DefaultStatusList2021StatusPurposeType
    encrypted: boolean
    paymentConditions?: PaymentCondition[]
    dkgOptions?: DkgOptions
    resourceVersion?: ResourcePayload['version']
    alsoKnownAs?: ResourcePayload['alsoKnownAs']
    statusListLength?: number
    statusListEncoding?: DefaultStatusList2021Encoding
    validUntil?: string
    returnSymmetricKey?: boolean
}

export interface ICheqdCreateUnencryptedStatusList2021Args {
    kms: string
    payload: StatusList2021ResourcePayload
    network: CheqdNetwork
    file?: string
    signInputs?: ISignInputs[]
    fee?: DidStdFee
}

export interface ICheqdBroadcastStatusList2021Args {
    kms: string
    payload: StatusList2021ResourcePayload
    network: CheqdNetwork
    file?: string
    signInputs?: ISignInputs[]
    fee?: DidStdFee
}

export interface ICheqdGenerateDidDocArgs {
    verificationMethod: VerificationMethods
    methodSpecificIdAlgo: MethodSpecificIdAlgo
    network: CheqdNetwork
}

export interface ICheqdGenerateDidDocWithLinkedResourceArgs extends ICheqdGenerateDidDocArgs {
    [key: string]: any
}

export interface ICheqdGenerateKeyPairArgs {
    [key: string]: any
}

export interface ICheqdGenerateVersionIdArgs {
    [key: string]: any
}

export interface ICheqdGenerateStatusList2021Args {
    length?: number
    buffer?: Uint8Array
    bitstringEncoding?: DefaultStatusList2021Encoding
}

export interface ICheqdIssueRevocableCredentialWithStatusList2021Args {
    issuanceOptions: ICreateVerifiableCredentialArgs
    statusOptions: {
        statusPurpose: 'revocation'
        statusListName: string
        statusListIndex?: number
        statusListVersion?: string
        statusListRangeStart?: number
        statusListRangeEnd?: number
        indexNotIn?: number[]
    }
}

export interface ICheqdIssueSuspendableCredentialWithStatusList2021Args {
    issuanceOptions: ICreateVerifiableCredentialArgs
    statusOptions: {
        statusPurpose: 'suspension'
        statusListName: string
        statusListIndex?: number
        statusListVersion?: string
        statusListRangeStart?: number
        statusListRangeEnd?: number
        indexNotIn?: number[]
    }
}

export interface ICheqdVerifyCredentialWithStatusList2021Args {
    credential: W3CVerifiableCredential
    verificationArgs?: IVerifyCredentialArgs
    fetchList?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdVerifyPresentationWithStatusList2021Args {
    presentation: VerifiablePresentation
    verificationArgs?: IVerifyPresentationArgs
    fetchList?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdCheckCredentialStatusWithStatusList2021Args {
    credential?: W3CVerifiableCredential
    statusOptions?: ICheqdCheckCredentialWithStatusList2021StatusOptions
    fetchList?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdRevokeCredentialWithStatusList2021Args {
    credential?: W3CVerifiableCredential
    revocationOptions?: ICheqdRevokeCredentialWithStatusList2021Options
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    paymentConditions?: PaymentCondition[]
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdRevokeBulkCredentialsWithStatusList2021Args {
    credentials?: W3CVerifiableCredential[]
    revocationOptions?: ICheqdRevokeBulkCredentialsWithStatusList2021Options
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    paymentConditions?: PaymentCondition[]
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdSuspendCredentialWithStatusList2021Args {
    credential?: W3CVerifiableCredential
    suspensionOptions?: ICheqdSuspendCredentialWithStatusList2021Options
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    paymentConditions?: PaymentCondition[]
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdSuspendBulkCredentialsWithStatusList2021Args {
    credentials?: W3CVerifiableCredential[]
    suspensionOptions?: ICheqdSuspendBulkCredentialsWithStatusList2021Options
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    paymentConditions?: PaymentCondition[]
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdUnsuspendCredentialWithStatusList2021Args {
    credential?: W3CVerifiableCredential
    unsuspensionOptions?: ICheqdUnsuspendCredentialWithStatusList2021Options
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    paymentConditions?: PaymentCondition[]
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdUnsuspendBulkCredentialsWithStatusList2021Args {
    credentials?: W3CVerifiableCredential[]
    unsuspensionOptions?: ICheqdUnsuspendBulkCredentialsWithStatusList2021Options
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    paymentConditions?: PaymentCondition[]
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    dkgOptions?: DkgOptions
    options?: ICheqdStatusList2021Options
}

export interface ICheqdTransactSendTokensArgs {
    recipientAddress: string
    amount: Coin
    memo?: string
    txBytes?: Uint8Array
    returnTxResponse?: boolean
}

export interface ICheqdObservePaymentConditionArgs {
    recipientAddress?: string
    amount?: Coin
    intervalInSeconds?: number
    blockHeight?: string
    comparator?: Extract<AccessControlConditionReturnValueComparator, '<' | '<='>
    network?: CheqdNetwork
    unifiedAccessControlCondition?: Required<CosmosAccessControlCondition>
    returnTxResponse?: boolean
}

export interface ICheqdStatusList2021Options {
    statusListFile?: string
    statusListInlineBitstring?: string
    [key: string]: any
}

export interface ICheqdRevokeCredentialWithStatusList2021Options {
    issuerDid: string
    statusListName: string
    statusListIndex: number
    statusListVersion?: string
}

export interface ICheqdRevokeBulkCredentialsWithStatusList2021Options {
    issuerDid: string
    statusListName: string
    statusListIndices: number[]
    statusListVersion?: string
}

export interface ICheqdSuspendCredentialWithStatusList2021Options {
    issuerDid: string
    statusListName: string
    statusListIndex: number
    statusListVersion?: string
}

export interface ICheqdSuspendBulkCredentialsWithStatusList2021Options {
    issuerDid: string
    statusListName: string
    statusListIndices: number[]
    statusListVersion?: string
}

export interface ICheqdUnsuspendCredentialWithStatusList2021Options {
    issuerDid: string
    statusListName: string
    statusListIndex: number
    statusListVersion?: string
}

export interface ICheqdUnsuspendBulkCredentialsWithStatusList2021Options {
    issuerDid: string
    statusListName: string
    statusListIndices: number[]
    statusListVersion?: string
}

export interface ICheqdCheckCredentialWithStatusList2021StatusOptions {
    issuerDid: string
    statusListName: string
    statusListIndex: number
    statusPurpose: DefaultStatusList2021StatusPurposeType
    statusListVersion?: string
}

export interface ICheqd extends IPluginMethodMap {
    [CreateIdentifierMethodName]: (args: ICheqdCreateIdentifierArgs, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>
    [UpdateIdentifierMethodName]: (args: ICheqdUpdateIdentifierArgs, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>,
    [DeactivateIdentifierMethodName]: (args: ICheqdDeactivateIdentifierArgs, context: IContext) => Promise<boolean>,
    [CreateResourceMethodName]: (args: ICheqdCreateLinkedResourceArgs, context: IContext) => Promise<boolean>,
    [CreateStatusList2021MethodName]: (args: ICheqdCreateStatusList2021Args, context: IContext) => Promise<CreateStatusList2021Result>,
    [BroadcastStatusList2021MethodName]: (args: ICheqdBroadcastStatusList2021Args, context: IContext) => Promise<boolean>,
    [GenerateDidDocMethodName]: (args: ICheqdGenerateDidDocArgs, context: IContext) => Promise<TExportedDIDDocWithKeys>,
    [GenerateDidDocWithLinkedResourceMethodName]: (args: ICheqdGenerateDidDocWithLinkedResourceArgs, context: IContext) => Promise<TExportedDIDDocWithLinkedResourceWithKeys>,
    [GenerateKeyPairMethodName]: (args: ICheqdGenerateKeyPairArgs, context: IContext) => Promise<TImportableEd25519Key>
    [GenerateVersionIdMethodName]: (args: ICheqdGenerateVersionIdArgs, context: IContext) => Promise<string>
    [GenerateStatusList2021MethodName]: (args: ICheqdGenerateStatusList2021Args, context: IContext) => Promise<string>
    [IssueRevocableCredentialWithStatusList2021MethodName]: (args: ICheqdIssueRevocableCredentialWithStatusList2021Args, context: IContext) => Promise<VerifiableCredential>
    [IssueSuspendableCredentialWithStatusList2021MethodName]: (args: ICheqdIssueSuspendableCredentialWithStatusList2021Args, context: IContext) => Promise<VerifiableCredential>
    [VerifyCredentialMethodName]: (args: ICheqdVerifyCredentialWithStatusList2021Args, context: IContext) => Promise<VerificationResult>
    [VerifyPresentationMethodName]: (args: ICheqdVerifyPresentationWithStatusList2021Args, context: IContext) => Promise<VerificationResult>
    [CheckCredentialStatusMethodName]: (args: ICheqdCheckCredentialStatusWithStatusList2021Args, context: IContext) => Promise<StatusCheckResult>
    [RevokeCredentialMethodName]: (args: ICheqdRevokeCredentialWithStatusList2021Args, context: IContext) => Promise<RevocationResult>
    [RevokeCredentialsMethodName]: (args: ICheqdRevokeBulkCredentialsWithStatusList2021Args, context: IContext) => Promise<BulkRevocationResult>
    [SuspendCredentialMethodName]: (args: ICheqdSuspendCredentialWithStatusList2021Args, context: IContext) => Promise<SuspensionResult>
    [SuspendCredentialsMethodName]: (args: ICheqdSuspendBulkCredentialsWithStatusList2021Args, context: IContext) => Promise<BulkSuspensionResult>
    [UnsuspendCredentialMethodName]: (args: ICheqdUnsuspendCredentialWithStatusList2021Args, context: IContext) => Promise<UnsuspensionResult>
    [UnsuspendCredentialsMethodName]: (args: ICheqdUnsuspendBulkCredentialsWithStatusList2021Args, context: IContext) => Promise<BulkUnsuspensionResult>
    [TransactSendTokensMethodName]: (args: ICheqdTransactSendTokensArgs, context: IContext) => Promise<TransactionResult>
    [ObservePaymentConditionMethodName]: (args: ICheqdObservePaymentConditionArgs, context: IContext) => Promise<ObservationResult>
}

export class Cheqd implements IAgentPlugin {
    readonly methods?: ICheqd
    readonly schema?: IAgentPluginSchema = {
        "components": {
            "schemas": {},
            "methods": {
                "cheqdCreateIdentifier": {
                    "description": "Create a new identifier",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateIdentifierArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdUpdateIdentifier": {
                    "description": "Update an identifier",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdUpdateIdentifierArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdDeactivateIdentifier": {
                    "description": "Deactivate an identifier",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdDeactivateIdentifierArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdCreateLinkedResource": {
                    "description": "Create a new resource",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateLinkedResource object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "boolean"
                    }
                },
                "cheqdCreateStatusList2021": {
                    "description": "Create a new Status List 2021",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdBroadcastStatusList2021": {
                    "description": "Broadcast a Status List 2021 to cheqd ledger",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdBroadcastStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateDidDoc": {
                    "description": "Generate a new DID document to use with `createIdentifier`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateDidDocArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateDidDocWithLinkedResource": {
                    "description": "Generate a new DID document to use with `createIdentifier` and / or `createResource`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateDidDocWithLinkedResourceArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateIdentityKeys": {
                    "description": "Generate a new key pair in hex to use with `createIdentifier`",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateIdentityKeysArgs object as any for extensibility"
                            }
                        }
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateVersionId": {
                    "description": "Generate a random uuid",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateVersionIdArgs object as any for extensibility"
                            }
                        },
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdGenerateStatusList2021": {
                    "description": "Generate a new Status List 2021",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateStatusList2021Args object as any for extensibility"
                            }
                        },
                    },
                    "returnType": {
                        "type": "string"
                    }
                },
                "cheqdIssueRevocableCredentialWithStatusList2021": {
                    "description": "Issue a revocable credential with a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdIssueCredentialWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdIssueSuspendableCredentialWithStatusList2021": {
                    "description": "Issue a suspendable credential with a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdIssueCredentialWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdVerifyCredential": {
                    "description": "Verify a credential, enhanced by revocation / suspension check with a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdVerifyCredentialWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdVerifyPresentation": {
                    "description": "Verify a presentation, enhanced by revocation / suspension check with a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdVerifyPresentationWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdCheckCredentialStatus": {
                    "description": "Check the revocation / suspension status of a credential with a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCheckCredentialStatusWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdRevokeCredential": {
                    "description": "Revoke a credential against a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdRevokeCredentialWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdRevokeCredentials": {
                    "description": "Revoke multiple credentials against a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdRevokeBulkCredentialsWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "array"
                    }
                },
                "cheqdSuspendCredential": {
                    "description": "Suspend a credential against a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdSuspendCredentialWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdSuspendCredentials": {
                    "description": "Suspend multiple credentials against a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdSuspendBulkCredentialsWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "array"
                    }
                },
                "cheqdUnsuspendCredential": {
                    "description": "Unsuspend a credential against a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "cheqdUnsuspendCredentialWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdUnsuspendCredentials": {
                    "description": "Unsuspend multiple credentials against a Status List 2021 as credential status registry",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdUnsuspendBulkCredentialsWithStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "array"
                    }
                },
                "cheqdTransactSendTokens": {
                    "description": "Send tokens from one account to another",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdTransactSendTokensArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                },
                "cheqdObservePaymentCondition": {
                    "description": "Observe payment conditions for a given set of payment conditions",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "cheqdObservePaymentConditionArgs object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
                    },
                    "returnType": {
                        "type": "object"
                    }
                }
            }
        }
    }
    private readonly supportedDidProviders: CheqdDIDProvider[]
    private didProvider: CheqdDIDProvider;
    private providerId: string;
    static readonly defaultStatusList2021Length: number = 16 * 1024 * 8 // 16KB in bits or 131072 bits / entries
    static readonly defaultContextV1 = 'https://www.w3.org/2018/credentials/v1'
    static readonly statusList2021Context = 'https://w3id.org/vc-status-list-2021/v1'


    constructor(args: { providers: CheqdDIDProvider[] }) {
        if (typeof args.providers !== 'object') {
            throw new Error('[did-provider-cheqd]: at least one did provider is required')
        }

        this.supportedDidProviders = args.providers
        this.didProvider = args.providers[0]
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        this.methods = {
            [CreateIdentifierMethodName]: this.CreateIdentifier.bind(this),
            [UpdateIdentifierMethodName]: this.UpdateIdentifier.bind(this),
            [DeactivateIdentifierMethodName]: this.DeactivateIdentifier.bind(this),
            [CreateResourceMethodName]: this.CreateResource.bind(this),
            [CreateStatusList2021MethodName]: this.CreateStatusList2021.bind(this),
            [BroadcastStatusList2021MethodName]: this.BroadcastStatusList2021.bind(this),
            [GenerateDidDocMethodName]: this.GenerateDidDoc.bind(this),
            [GenerateDidDocWithLinkedResourceMethodName]: this.GenerateDidDocWithLinkedResource.bind(this),
            [GenerateKeyPairMethodName]: this.GenerateIdentityKeys.bind(this),
            [GenerateVersionIdMethodName]: this.GenerateVersionId.bind(this),
            [GenerateStatusList2021MethodName]: this.GenerateStatusList2021.bind(this),
            [IssueRevocableCredentialWithStatusList2021MethodName]: this.IssueRevocableCredentialWithStatusList2021.bind(this),
            [IssueSuspendableCredentialWithStatusList2021MethodName]: this.IssueSuspendableCredentialWithStatusList2021.bind(this),
            [VerifyCredentialMethodName]: this.VerifyCredentialWithStatusList2021.bind(this),
            [VerifyPresentationMethodName]: this.VerifyPresentationWithStatusList2021.bind(this),
            [CheckCredentialStatusMethodName]: this.CheckCredentialStatusWithStatusList2021.bind(this),
            [RevokeCredentialMethodName]: this.RevokeCredentialWithStatusList2021.bind(this),
            [RevokeCredentialsMethodName]: this.RevokeBulkCredentialsWithStatusList2021.bind(this),
            [SuspendCredentialMethodName]: this.SuspendCredentialWithStatusList2021.bind(this),
            [SuspendCredentialsMethodName]: this.SuspendBulkCredentialsWithStatusList2021.bind(this),
            [UnsuspendCredentialMethodName]: this.UnsuspendCredentialWithStatusList2021.bind(this),
            [UnsuspendCredentialsMethodName]: this.UnsuspendBulkCredentialsWithStatusList2021.bind(this),
            [TransactSendTokensMethodName]: this.TransactSendTokens.bind(this),
            [ObservePaymentConditionMethodName]: this.ObservePaymentCondition.bind(this),
        }
    }

    private async CreateIdentifier(args: ICheqdCreateIdentifierArgs, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.alias !== 'string') {
            throw new Error('[did-provider-cheqd]: alias is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        const provider = await Cheqd.loadProvider(<DIDDocument>args.document, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await context.agent.didManagerCreate({
            kms: args.kms,
            alias: args.alias,
            provider: this.providerId,
            options: {
                document: args.document,
                keys: args.keys,
                versionId: args?.versionId,
                fee: args?.fee
            }
        })
    }

    private async UpdateIdentifier(args: ICheqdUpdateIdentifierArgs, context: IContext): Promise<Omit<IIdentifier, 'provider'>> {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        const provider = await Cheqd.loadProvider(<DIDDocument>args.document, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await context.agent.didManagerUpdate({
            did: args.document.id,
            document: args.document,
            options: {
                kms: args.kms,
                keys: args.keys,
                versionId: args?.versionId,
                fee: args?.fee
            }
        })
    }

    private async DeactivateIdentifier(args: ICheqdDeactivateIdentifierArgs, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.document !== 'object') {
            throw new Error('[did-provider-cheqd]: document object is required')
        }

        const provider = await Cheqd.loadProvider(<DIDDocument>args.document, this.supportedDidProviders)

        this.didProvider = provider
        this.providerId = Cheqd.generateProviderId(this.didProvider.network)

        return await this.didProvider.deactivateIdentifier({
            did: args.document.id,
            document: args.document,
            options: {
                keys: args.keys,
                fee: args?.fee
            }
        }, context)
    }

    private async CreateResource(args: ICheqdCreateLinkedResourceArgs, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.payload !== 'object') {
            throw new Error('[did-provider-cheqd]: payload object is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        if (args?.file) {
            args.payload.data = await Cheqd.getFile(args.file)
        }

        if (typeof args?.payload?.data === 'string') {
            args.payload.data = fromString(args.payload.data, 'base64')
        }

        this.providerId = Cheqd.generateProviderId(args.network)
        this.didProvider = await Cheqd.loadProvider({ id: this.providerId } as DIDDocument, this.supportedDidProviders)

        return await this.didProvider.createResource({
            options: {
                kms: args.kms,
                payload: args.payload,
                signInputs: args.signInputs,
                fee: args?.fee
            }
        }, context)
    }

    private async CreateStatusList2021(args: ICheqdCreateStatusList2021Args, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.issuerDid !== 'string' || !args.issuerDid) {
            throw new Error('[did-provider-cheqd]: issuerDid is required')
        }

        if (typeof args.statusListName !== 'string' || !args.statusListName) {
            throw new Error('[did-provider-cheqd]: statusListName is required')
        }

        if (typeof args.statusPurpose !== 'string' || !args.statusPurpose) {
            throw new Error('[did-provider-cheqd]: statusPurpose is required')
        }

        if (typeof args.encrypted === 'undefined') {
            throw new Error('[did-provider-cheqd]: encrypted is required')
        }

        // validate statusPurpose
        if (!Object.values(DefaultStatusList2021StatusPurposeTypes).includes(args.statusPurpose)) {
            throw new Error(`[did-provider-cheqd]: statusPurpose must be one of ${Object.values(DefaultStatusList2021StatusPurposeTypes).join(', ')}`)
        }

        // validate statusListLength
        if (args?.statusListLength) {
            if (typeof args.statusListLength !== 'number') {
                throw new Error('[did-provider-cheqd]: statusListLength must be number')
            }

            if (args.statusListLength < Cheqd.defaultStatusList2021Length) {
                throw new Error(`[did-provider-cheqd]: statusListLength must be greater than or equal to ${Cheqd.defaultStatusList2021Length} number of entries`)
            }
        }

        // validate statusListEncoding
        if (args?.statusListEncoding) {
            if (typeof args.statusListEncoding !== 'string') {
                throw new Error('[did-provider-cheqd]: statusListEncoding must be string')
            }

            if (!Object.values(DefaultStatusList2021Encodings).includes(args.statusListEncoding)) {
                throw new Error(`[did-provider-cheqd]: statusListEncoding must be one of ${Object.values(DefaultStatusList2021Encodings).join(', ')}`)
            }
        }

        // validate validUntil
        if (args?.validUntil) {
            if (typeof args.validUntil !== 'string') {
                throw new Error('[did-provider-cheqd]: validUntil must be string')
            }

            if (new Date() <= new Date(args.validUntil)) {
                throw new Error('[did-provider-cheqd]: validUntil must be greater than current date')
            }
        }

        // validate args in pairs - case: encrypted
        if (args.encrypted) {
            // validate paymentConditions
            if (!args?.paymentConditions || !args?.paymentConditions?.length || !Array.isArray(args?.paymentConditions) || args?.paymentConditions.length === 0) { 
                throw new Error('[did-provider-cheqd]: paymentConditions is required')
            }

            if (!args?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
            }

            if (!args?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
            }

            if (!args?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
            }
        }

        // get network
        const network = args.issuerDid.split(':')[2]

        // generate bitstring
        const bitstring = await context.agent[GenerateStatusList2021MethodName]({ length: args?.statusListLength || Cheqd.defaultStatusList2021Length, bitstringEncoding: args?.statusListEncoding || DefaultStatusList2021Encodings.base64url })

        // construct data and metadata tuple
        const data = args.encrypted
            ? (await (async function (that: Cheqd) {
                // instantiate dkg-threshold client, in which case lit-protocol is used
                const lit = await LitProtocol.create({
                    chain: args?.dkgOptions?.chain || that.didProvider.dkgOptions.chain,
                    litNetwork: args?.dkgOptions?.network || that.didProvider.dkgOptions.network,
                })

                // construct access control conditions
                const unifiedAccessControlConditions = await Promise.all(args.paymentConditions!.map(async (condition) => {
                    switch (condition.type) {
                        case AccessControlConditionTypes.timelockPayment:
                            return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                    key: '$.tx_responses.*.timestamp',
                                    comparator: '<=',
                                    value: `${condition.intervalInSeconds}`,
                                },
                                condition.feePaymentAmount,
                                condition.feePaymentAddress,
                                condition?.blockHeight,
                                args?.dkgOptions?.chain || that.didProvider.dkgOptions.chain
                            )
                        default:
                            throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                    }
                }))

                // encrypt bitstring
                const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditions, true)

                // return result tuple
                switch (args.statusPurpose) {
                    case DefaultStatusList2021StatusPurposeTypes.revocation:
                        return [{
                            StatusList2021: {
                                statusPurpose: args.statusPurpose,
                                encodedList: await blobToHexString(encryptedString),
                                validFrom: new Date().toISOString(),
                                validUntil: args?.validUntil
                            },
                            metadata: {
                                type: DefaultStatusList2021ResourceTypes.revocation,
                                encrypted: true,
                                encoding: args?.statusListEncoding || DefaultStatusList2021Encodings.base64url,
                                encryptedSymmetricKey,
                                paymentConditions: args.paymentConditions
                            }
                        } satisfies StatusList2021Revocation,
                        {
                            symmetricKey: toString(symmetricKey!, 'hex'),
                            encryptedSymmetricKey,
                            encryptedString: await blobToHexString(encryptedString),
                        }
                    ] satisfies [StatusList2021Revocation, { symmetricKey: string, encryptedSymmetricKey: string, encryptedString: string }]
                    case DefaultStatusList2021StatusPurposeTypes.suspension:
                        return [{
                            StatusList2021: {
                                statusPurpose: args.statusPurpose,
                                encodedList: await blobToHexString(encryptedString),
                                validFrom: new Date().toISOString(),
                                validUntil: args?.validUntil
                            },
                            metadata: {
                                type: DefaultStatusList2021ResourceTypes.suspension,
                                encrypted: true,
                                encoding: args?.statusListEncoding || DefaultStatusList2021Encodings.base64url,
                                encryptedSymmetricKey,
                                paymentConditions: args.paymentConditions
                            }
                        } satisfies StatusList2021Suspension,
                        {
                            symmetricKey: toString(symmetricKey!, 'hex'),
                            encryptedSymmetricKey,
                            encryptedString: await blobToHexString(encryptedString),
                        }
                    ] satisfies [StatusList2021Suspension, { symmetricKey: string, encryptedSymmetricKey: string, encryptedString: string }]
                    default:
                        throw new Error(`[did-provider-cheqd]: status purpose is not valid ${args.statusPurpose}`)
                }
            }(this)))
            : (await (async function () {
                switch (args.statusPurpose) {
                    case DefaultStatusList2021StatusPurposeTypes.revocation:
                        return [{
                            StatusList2021: {
                                statusPurpose: args.statusPurpose,
                                encodedList: bitstring,
                                validFrom: new Date().toISOString(),
                                validUntil: args?.validUntil
                            },
                            metadata: {
                                type: DefaultStatusList2021ResourceTypes.revocation,
                                encrypted: false,
                                encoding: args?.statusListEncoding || DefaultStatusList2021Encodings.base64url,
                            }
                        } satisfies StatusList2021Revocation,
                        undefined
                    ] satisfies [StatusList2021Revocation, undefined]
                    case DefaultStatusList2021StatusPurposeTypes.suspension:
                        return [{
                            StatusList2021: {
                                statusPurpose: args.statusPurpose,
                                encodedList: bitstring,
                                validFrom: new Date().toISOString(),
                                validUntil: args?.validUntil
                            },
                            metadata: {
                                type: DefaultStatusList2021ResourceTypes.suspension,
                                encrypted: false,
                                encoding: args?.statusListEncoding || DefaultStatusList2021Encodings.base64url,
                            }
                        } satisfies StatusList2021Suspension,
                        undefined
                    ] satisfies [StatusList2021Suspension, undefined]
                    default:
                        throw new Error('[did-provider-cheqd]: statusPurpose is not valid')
                }
            }()))

        // construct payload
        const payload = {
            id: v4(),
            collectionId: args.issuerDid.split(':').reverse()[0],
            name: args.statusListName,
            resourceType: DefaultStatusList2021ResourceTypes[args.statusPurpose],
            version: args?.resourceVersion || new Date().toISOString(),
            alsoKnownAs: args?.alsoKnownAs || [],
            data: fromString(JSON.stringify(data[0]), 'utf-8'),
        } satisfies StatusList2021ResourcePayload

        // return result
        return {
            created: await context.agent[BroadcastStatusList2021MethodName]({ kms: args.kms, payload, network: network as CheqdNetwork }),
            resource: data[0],
            resourceMetadata: await Cheqd.fetchStatusList2021Metadata({ credentialStatus: { id: `${DefaultResolverUrl}${args.issuerDid}?resourceName=${args.statusListName}&resourceType=${DefaultStatusList2021ResourceTypes[args.statusPurpose]}`, type: 'StatusList2021Entry' } } as VerifiableCredential),
            encrypted: args.encrypted,
            symmetricKey: args?.returnSymmetricKey ? data[1]?.symmetricKey : undefined,
        } satisfies CreateStatusList2021Result
    }

    private async BroadcastStatusList2021(args: ICheqdBroadcastStatusList2021Args, context: IContext) {
        if (typeof args.kms !== 'string') {
            throw new Error('[did-provider-cheqd]: kms is required')
        }

        if (typeof args.payload !== 'object') {
            throw new Error('[did-provider-cheqd]: payload object is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        if (args?.file) {
            args.payload.data = await Cheqd.getFile(args.file)
        }

        if (typeof args?.payload?.data === 'string') {
            args.payload.data = fromString(args.payload.data, 'base64')
        }

        // TODO: validate data as per bitstring

        // validate resource type
        if (!Object.values(DefaultStatusList2021ResourceTypes).includes(args?.payload?.resourceType)) {
            throw new Error(`[did-provider-cheqd]: resourceType must be one of ${Object.values(DefaultStatusList2021ResourceTypes).join(', ')}`)
        }

        this.providerId = Cheqd.generateProviderId(args.network)
        this.didProvider = await Cheqd.loadProvider({ id: this.providerId } as DIDDocument, this.supportedDidProviders)

        return await this.didProvider.createResource({
            options: {
                kms: args.kms,
                payload: args.payload,
                signInputs: args.signInputs,
                fee: args?.fee
            }
        }, context)
    }

    private async GenerateDidDoc(
        args: ICheqdGenerateDidDocArgs, 
        context: IContext
    ): Promise<TExportedDIDDocWithKeys> {
        if (typeof args.verificationMethod !== 'string') {
            throw new Error('[did-provider-cheqd]: verificationMethod is required')
        }

        if (typeof args.methodSpecificIdAlgo !== 'string') {
            throw new Error('[did-provider-cheqd]: methodSpecificIdAlgo is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        const keyPair = createKeyPairBase64()
        const keyPairHex: IKeyPair = { publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'), privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex') }
        const verificationKeys = createVerificationKeys(keyPair.publicKey, args.methodSpecificIdAlgo, 'key-1', args.network)
        const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys])

        return {
            didDoc: createDidPayload(verificationMethods, [verificationKeys]),
            versionId: v4(),
            keys: [
                {
                    publicKeyHex: keyPairHex.publicKey,
                    privateKeyHex: keyPairHex.privateKey,
                    kid: keyPairHex.publicKey,
                    type: 'Ed25519'
                }
            ]
        }
    }

    private async GenerateDidDocWithLinkedResource(args: any, context: IContext): Promise<TExportedDIDDocWithLinkedResourceWithKeys> {
        if (typeof args.verificationMethod !== 'string') {
            throw new Error('[did-provider-cheqd]: verificationMethod is required')
        }

        if (typeof args.methodSpecificIdAlgo !== 'string') {
            throw new Error('[did-provider-cheqd]: methodSpecificIdAlgo is required')
        }

        if (typeof args.network !== 'string') {
            throw new Error('[did-provider-cheqd]: network is required')
        }

        const keyPair = createKeyPairBase64()
        const keyPairHex: IKeyPair = { publicKey: toString(fromString(keyPair.publicKey, 'base64'), 'hex'), privateKey: toString(fromString(keyPair.privateKey, 'base64'), 'hex') }
        const verificationKeys = createVerificationKeys(keyPair.publicKey, args.methodSpecificIdAlgo, 'key-1', args.network)
        const verificationMethods = createDidVerificationMethod([args.verificationMethod], [verificationKeys])
        const payload = createDidPayload(verificationMethods, [verificationKeys])

        return {
            didDoc: payload,
            versionId: v4(),
            keys: [
                {
                    publicKeyHex: keyPairHex.publicKey,
                    privateKeyHex: keyPairHex.privateKey,
                    kid: keyPairHex.publicKey,
                    type: 'Ed25519'
                }
            ],
            linkedResource: {
                id: v4(),
                collectionId: payload.id.split(':').reverse()[0],
                name: 'sample json resource',
                version: '1.0.0',
                resourceType: 'SampleResource',
                alsoKnownAs: [],
                data: toString(new TextEncoder().encode(
                    JSON.stringify({ sample: 'json' })
                ), 'base64'),
            }
        }
    }

    private async GenerateIdentityKeys(args: any, context: IContext): Promise<TImportableEd25519Key> {
        const keyPair = createKeyPairHex()
        return {
            publicKeyHex: keyPair.publicKey,
            privateKeyHex: keyPair.privateKey,
            kid: keyPair.publicKey,
            type: 'Ed25519'
        }
    }

    private async GenerateVersionId(args: any, context: IContext): Promise<string> {
        return v4()
    }

    private async GenerateStatusList2021(args: ICheqdGenerateStatusList2021Args, context: IContext): Promise<Bitstring> {
        const statusList = args?.buffer
            ? new StatusList({ buffer: args.buffer })
            : new StatusList({ length: args?.length || Cheqd.defaultStatusList2021Length })

        const encoded = await statusList.encode() as Bitstring

        switch (args?.bitstringEncoding) {
            case 'base64url':
                return encoded
            case 'base64':
                return toString(fromString(encoded, 'base64url'), 'base64')
            case 'hex':
                return toString(fromString(encoded, 'base64url'), 'hex')
            default:
                return encoded
        }
    }

    private async IssueRevocableCredentialWithStatusList2021(args: ICheqdIssueRevocableCredentialWithStatusList2021Args, context: IContext): Promise<VerifiableCredential> {
        // generate index
        const statusListIndex = args.statusOptions.statusListIndex || await randomFromRange(args.statusOptions.statusListRangeStart || 0, (args.statusOptions.statusListRangeEnd || Cheqd.defaultStatusList2021Length) - 1, args.statusOptions.indexNotIn || []) 

        // construct issuer
        const issuer = ((args.issuanceOptions.credential.issuer as { id: string }).id)
            ? (args.issuanceOptions.credential.issuer as { id: string }).id
            : args.issuanceOptions.credential.issuer as string

        // generate status list credential
        const statusListCredential = `${DefaultResolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}&resourceType=StatusList2021Revocation`

        // construct credential status
        const credentialStatus = {
            id: `${statusListCredential}#${statusListIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: 'revocation',
            statusListIndex: `${statusListIndex}`,
        }

        // add credential status to credential
        args.issuanceOptions.credential.credentialStatus = credentialStatus

        // add relevant context
        args.issuanceOptions.credential['@context'] = function() {
            // if no context is provided, add default context
            if (!args.issuanceOptions.credential['@context']) {
                return [Cheqd.defaultContextV1, Cheqd.statusList2021Context]
            }

            // if context is provided as an array, add default context if it is not already present
            if (Array.isArray(args.issuanceOptions.credential['@context'])) {
                if (args.issuanceOptions.credential['@context'].length === 0) {
                    return [Cheqd.defaultContextV1, Cheqd.statusList2021Context]
                }

                if (!args.issuanceOptions.credential['@context'].includes(Cheqd.statusList2021Context)) {
                    return [...args.issuanceOptions.credential['@context'], Cheqd.statusList2021Context]
                }
            }

            // if context is provided as a string, add default context if it is not already present
            if (typeof args.issuanceOptions.credential['@context'] === 'string') return [Cheqd.defaultContextV1, Cheqd.statusList2021Context]
        }()

        // create a credential
        const credential = await context.agent.createVerifiableCredential(args.issuanceOptions)

        return credential
    }

    private async IssueSuspendableCredentialWithStatusList2021(args: ICheqdIssueSuspendableCredentialWithStatusList2021Args, context: IContext): Promise<VerifiableCredential> {
        // generate index
        const statusListIndex = args.statusOptions.statusListIndex || await randomFromRange(args.statusOptions.statusListRangeStart || 0, (args.statusOptions.statusListRangeEnd || Cheqd.defaultStatusList2021Length) - 1, args.statusOptions.indexNotIn || []) 

        // construct issuer
        const issuer = ((args.issuanceOptions.credential.issuer as { id: string }).id)
            ? (args.issuanceOptions.credential.issuer as { id: string }).id
            : args.issuanceOptions.credential.issuer as string

        // generate status list credential
        const statusListCredential = `${DefaultResolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}&resourceType=StatusList2021Suspension`

        // construct credential status
        const credentialStatus = {
            id: `${statusListCredential}#${statusListIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: 'suspension',
            statusListIndex: `${statusListIndex}`,
        }

        // add credential status to credential
        args.issuanceOptions.credential.credentialStatus = credentialStatus

        // add relevant context
        args.issuanceOptions.credential['@context'] = function() {
            // if no context is provided, add default context
            if (!args.issuanceOptions.credential['@context']) {
                return [Cheqd.defaultContextV1, Cheqd.statusList2021Context]
            }

            // if context is provided as an array, add default context if it is not already present
            if (Array.isArray(args.issuanceOptions.credential['@context'])) {
                if (args.issuanceOptions.credential['@context'].length === 0) {
                    return [Cheqd.defaultContextV1, Cheqd.statusList2021Context]
                }

                if (!args.issuanceOptions.credential['@context'].includes(Cheqd.statusList2021Context)) {
                    return [...args.issuanceOptions.credential['@context'], Cheqd.statusList2021Context]
                }
            }

            // if context is provided as a string, add default context if it is not already present
            if (typeof args.issuanceOptions.credential['@context'] === 'string') return [Cheqd.defaultContextV1, Cheqd.statusList2021Context]
        }()

        // create a credential
        const credential = await context.agent.createVerifiableCredential(args.issuanceOptions)

        return credential
    }

    private async VerifyCredentialWithStatusList2021(args: ICheqdVerifyCredentialWithStatusList2021Args, context: IContext): Promise<VerificationResult> {
        // verify default policies
        const verificationResult = await context.agent.verifyCredential({
            ...args?.verificationArgs,
            credential: args.credential,
            policies: {
                ...args?.verificationArgs?.policies,
                credentialStatus: false
            },
        } satisfies IVerifyCredentialArgs)

        // early return if verification failed
        if (!verificationResult.verified) {
            return { verified: false, error: verificationResult.error }
        }

        // if jwt credential, decode it
        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential

        // define dkg options, if provided
        args.dkgOptions ||= this.didProvider.dkgOptions

        // verify credential status
        switch (credential.credentialStatus?.statusPurpose) {
            case 'revocation':
                if (await Cheqd.checkRevoked(credential, { ...args.options, topArgs: args })) return { ...verificationResult, revoked: true }
                return { ...verificationResult, revoked: false }
            case 'suspension':
                if (await Cheqd.checkSuspended(credential, { ...args.options, topArgs: args })) return { ...verificationResult, suspended: true }
                return { ...verificationResult, suspended: false }
            default:
                throw new Error(`[did-provider-cheqd]: verify credential: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }
    }

    private async VerifyPresentationWithStatusList2021(args: ICheqdVerifyPresentationWithStatusList2021Args, context: IContext): Promise<VerificationResult> {
        // verify default policies
        const verificationResult = await context.agent.verifyPresentation({
            ...args?.verificationArgs,
            presentation: args.presentation,
            policies: {
                ...args?.verificationArgs?.policies,
                credentialStatus: false
            },
        } satisfies IVerifyPresentationArgs)

        // early return if verification failed
        if (!verificationResult.verified) {
            return { verified: false, error: verificationResult.error }
        }

        // early return if no verifiable credentials are provided
        if (!args.presentation.verifiableCredential) throw new Error('[did-provider-cheqd]: verify presentation: presentation.verifiableCredential is required')

        // define dkg options, if provided
        args.dkgOptions ||= this.didProvider.dkgOptions

        // verify credential(s) status(es)
        for (let credential of args.presentation.verifiableCredential) {
            // if jwt credential, decode it
            if (typeof credential === 'string') credential = await Cheqd.decodeCredentialJWT(credential)

            switch (credential.credentialStatus?.statusPurpose) {
                case 'revocation':
                    if (await Cheqd.checkRevoked(credential, { ...args.options, topArgs: args })) return { ...verificationResult, revoked: true }
                    break
                case 'suspension':
                    if (await Cheqd.checkSuspended(credential, { ...args.options, topArgs: args })) return { ...verificationResult, suspended: true }
                    break
                default:
                    throw new Error(`[did-provider-cheqd]: verify presentation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
            }
        }

        return { ...verificationResult, verified: true }
    }

    private async CheckCredentialStatusWithStatusList2021(args: ICheqdCheckCredentialStatusWithStatusList2021Args, context: IContext): Promise<StatusCheckResult> {
        // verify credential, if provided and status options are not
        if (args?.credential && !args?.statusOptions) {
            const verificationResult = await context.agent.verifyCredential({
                credential: args.credential,
                policies: {
                    credentialStatus: false
                }
            } satisfies IVerifyCredentialArgs)

            // early return if verification failed
            if (!verificationResult.verified) {
                return { revoked: false, error: verificationResult.error }
            }
        }

        // if status options are provided, give precedence
        if (args?.statusOptions) {
            // validate status options - case: statusOptions.issuerDid
            if (!args.statusOptions.issuerDid) throw new Error('[did-provider-cheqd]: check status: statusOptions.issuerDid is required')

            // validate status options - case: statusOptions.statusListName
            if (!args.statusOptions.statusListName) throw new Error('[did-provider-cheqd]: check status: statusOptions.statusListName is required')

            // validate status options - case: statusOptions.statusListIndex
            if (!args.statusOptions.statusPurpose) throw new Error('[did-provider-cheqd]: check status: statusOptions.statusListIndex is required')

            // validate status options - case: statusOptions.statusListIndex
            if (!args.statusOptions.statusListIndex) throw new Error('[did-provider-cheqd]: check status: statusOptions.statusListIndex is required')

            // generate resource type
            const resourceType = args.statusOptions.statusPurpose === 'revocation' ? 'StatusList2021Revocation' : 'StatusList2021Suspension'

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.statusOptions.issuerDid}?resourceName=${args.statusOptions.statusListName}&resourceType=${resourceType}`

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
                proof: {}
            }
        }

        // validate args - case: credential
        if (!args.credential) throw new Error('[did-provider-cheqd]: revocation: credential is required')

        // if jwt credential, decode it
        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential

        // define dkg options, if provided
        args.dkgOptions ||= this.didProvider.dkgOptions

        switch (credential.credentialStatus?.statusPurpose) {
            case 'revocation':
                if (await Cheqd.checkRevoked(credential, { ...args.options, topArgs: args })) return { revoked: true }
                return { revoked: false }
            case 'suspension':
                if (await Cheqd.checkSuspended(credential, { ...args.options, topArgs: args })) return { suspended: true }
                return { suspended: false }
            default:
                throw new Error(`[did-provider-cheqd]: check status: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }
    }

    private async RevokeCredentialWithStatusList2021(args: ICheqdRevokeCredentialWithStatusList2021Args, context: IContext): Promise<RevocationResult> {
        // verify credential, if provided and revocation options are not
        if (args?.credential && !args?.revocationOptions) {
            const verificationResult = await context.agent.verifyCredential({
                credential: args.credential,
                policies: {
                    credentialStatus: false
                }
            } satisfies IVerifyCredentialArgs)

            // early return if verification failed
            if (!verificationResult.verified) {
                return { revoked: false, error: verificationResult.error }
            }
        }

        // if revocation options are provided, give precedence
        if (args?.revocationOptions) {
            // validate revocation options - case: revocationOptions.issuerDid
            if (!args.revocationOptions.issuerDid) throw new Error('[did-provider-cheqd]: revocation: revocationOptions.issuerDid is required')

            // validate revocation options - case: revocationOptions.statusListName
            if (!args.revocationOptions.statusListName) throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListName is required')

            // validate revocation options - case: revocationOptions.statusListIndex
            if (!args.revocationOptions.statusListIndex) throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListIndex is required')

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.revocationOptions.issuerDid}?resourceName=${args.revocationOptions.statusListName}&resourceType=StatusList2021Revocation`

            // construct credential status
            args.credential = {
                '@context': [],
                issuer: args.revocationOptions.issuerDid,
                credentialSubject: {},
                credentialStatus: {
                    id: `${statusListCredential}#${args.revocationOptions.statusListIndex}`,
                    type: 'StatusList2021Entry',
                    statusPurpose: 'revocation',
                    statusListIndex: `${args.revocationOptions.statusListIndex}`,
                },
                issuanceDate: '',
                proof: {}
            }
        }

        // validate args - case: credential
        if (!args.credential) throw new Error('[did-provider-cheqd]: revocation: credential is required')

        // if jwt credential, decode it
        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential

        // validate status purpose
        if (credential.credentialStatus?.statusPurpose !== 'revocation') {
            throw new Error(`[did-provider-cheqd]: revocation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }

        // validate args in pairs - case: statusListFile and statusList
        if (args.options?.statusListFile && args.options?.statusList) {
            throw new Error('[did-provider-cheqd]: revocation: statusListFile and statusList are mutually exclusive')
        }

        // validate args in pairs - case: statusListFile and fetchList
        if (args.options?.statusListFile && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: revocation: statusListFile and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: statusList and fetchList
        if (args.options?.statusList && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: revocation: statusList and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: publish
        if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
            throw new Error('[did-provider-cheqd]: revocation: publish requires statusListFile or statusList, if fetchList is disabled')
        }

        // define dkg options, if provided
        args.dkgOptions ||= this.didProvider.dkgOptions

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
                fee: args?.options?.fee
            }
        })
    }

    private async RevokeBulkCredentialsWithStatusList2021(args: ICheqdRevokeBulkCredentialsWithStatusList2021Args, context: IContext): Promise<BulkRevocationResult> {
        // verify credential, if provided and revocation options are not
        if (args?.credentials && !args?.revocationOptions) {
            
            const verificationResult = await Promise.all(args.credentials.map(async (credential) => {
                return await context.agent.verifyCredential({
                    credential,
                    policies: {
                        credentialStatus: false
                    }
                } satisfies IVerifyCredentialArgs)
            }))

            // early return if verification failed for any credential
            if (verificationResult.some(result => !result.verified)) {
                // define verified
                return { revoked: Array(args.credentials.length).fill(false), error: verificationResult.find(result => !result.verified)!.error || { message: 'verification: could not verify credential' }  }
            }
        }

        // if revocation options are provided, give precedence
        if (args?.revocationOptions) {
            // validate revocation options - case: revocationOptions.issuerDid
            if (!args.revocationOptions.issuerDid) throw new Error('[did-provider-cheqd]: revocation: revocationOptions.issuerDid is required')

            // validate revocation options - case: revocationOptions.statusListName
            if (!args.revocationOptions.statusListName) throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListName is required')

            // validate revocation options - case: revocationOptions.statusListIndices
            if (!args.revocationOptions.statusListIndices || !args.revocationOptions.statusListIndices.length || args.revocationOptions.statusListIndices.length === 0 || !args.revocationOptions.statusListIndices.every(index => !isNaN(+index))) throw new Error('[did-provider-cheqd]: revocation: revocationOptions.statusListIndex is required and must be an array of indices')

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.revocationOptions.issuerDid}?resourceName=${args.revocationOptions.statusListName}&resourceType=StatusList2021Revocation`

            // construct credential status
            args.credentials = args.revocationOptions.statusListIndices.map(index => ({
                '@context': [],
                issuer: args.revocationOptions!.issuerDid,
                credentialSubject: {},
                credentialStatus: {
                    id: `${statusListCredential}#${index}`,
                    type: 'StatusList2021Entry',
                    statusPurpose: 'revocation',
                    statusListIndex: `${index}`,
                },
                issuanceDate: '',
                proof: {}
            }))
        }

        // validate args - case: credentials
        if (!args.credentials || !args.credentials.length || args.credentials.length === 0) throw new Error('[did-provider-cheqd]: revocation: credentials is required and must be an array of credentials')

        // if jwt credentials, decode them
        const credentials = await Promise.all(args.credentials.map(async credential => typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential))

        // validate args in pairs - case: statusListFile and statusList
        if (args.options?.statusListFile && args.options?.statusList) {
            throw new Error('[did-provider-cheqd]: revocation: statusListFile and statusList are mutually exclusive')
        }

        // validate args in pairs - case: statusListFile and fetchList
        if (args.options?.statusListFile && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: revocation: statusListFile and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: statusList and fetchList
        if (args.options?.statusList && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: revocation: statusList and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: publish
        if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
            throw new Error('[did-provider-cheqd]: revocation: publish requires statusListFile or statusList, if fetchList is disabled')
        }

        // define dkg options, if provided
        args.dkgOptions ||= this.didProvider.dkgOptions

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
                fee: args?.options?.fee
            }
        })
    }

    private async SuspendCredentialWithStatusList2021(args: ICheqdSuspendCredentialWithStatusList2021Args, context: IContext): Promise<SuspensionResult> {
        // verify credential, if provided and suspension options are not
        if (args?.credential && !args?.suspensionOptions) {
            const verificationResult = await context.agent.verifyCredential({
                credential: args.credential,
                policies: {
                    credentialStatus: false
                }
            } satisfies IVerifyCredentialArgs)

            // early return if verification failed
            if (!verificationResult.verified) {
                return { suspended: false, error: verificationResult.error }
            }
        }

        // if suspension options are provided, give precedence
        if (args?.suspensionOptions) {
            // validate suspension options - case: suspensionOptions.issuerDid
            if (!args.suspensionOptions.issuerDid) throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.issuerDid is required')

            // validate suspension options - case: suspensionOptions.statusListName
            if (!args.suspensionOptions.statusListName) throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListName is required')

            // validate suspension options - case: suspensionOptions.statusListIndex
            if (!args.suspensionOptions.statusListIndex) throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListIndex is required')

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.suspensionOptions.issuerDid}?resourceName=${args.suspensionOptions.statusListName}&resourceType=StatusList2021Suspension`

            // construct credential status
            args.credential = {
                '@context': [],
                issuer: args.suspensionOptions.issuerDid,
                credentialSubject: {},
                credentialStatus: {
                    id: `${statusListCredential}#${args.suspensionOptions.statusListIndex}`,
                    type: 'StatusList2021Entry',
                    statusPurpose: 'suspension',
                    statusListIndex: `${args.suspensionOptions.statusListIndex}`,
                },
                issuanceDate: '',
                proof: {}
            }
        }

        // validate args - case: credential
        if (!args.credential) throw new Error('[did-provider-cheqd]: suspension: credential is required')

        // if jwt credential, decode it
        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential

        // validate status purpose
        if (credential.credentialStatus?.statusPurpose !== 'suspension') {
            throw new Error(`[did-provider-cheqd]: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }

        // validate args in pairs - case: statusListFile and statusList
        if (args.options?.statusListFile && args.options?.statusList) {
            throw new Error('[did-provider-cheqd]: suspension: statusListFile and statusList are mutually exclusive')
        }

        // validate args in pairs - case: statusListFile and fetchList
        if (args.options?.statusListFile && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: suspension: statusListFile and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: statusList and fetchList
        if (args.options?.statusList && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: suspension: statusList and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: publish
        if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
            throw new Error('[did-provider-cheqd]: suspension: publish requires statusListFile or statusList, if fetchList is disabled')
        }

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
                fee: args?.options?.fee
            }
        })
    }

    private async SuspendBulkCredentialsWithStatusList2021(args: ICheqdSuspendBulkCredentialsWithStatusList2021Args, context: IContext): Promise<BulkSuspensionResult> {
        // verify credential, if provided and suspension options are not
        if (args?.credentials && !args?.suspensionOptions) {
            
            const verificationResult = await Promise.all(args.credentials.map(async (credential) => {
                return await context.agent.verifyCredential({
                    credential,
                    policies: {
                        credentialStatus: false
                    }
                } satisfies IVerifyCredentialArgs)
            }))

            // early return if verification failed for any credential
            if (verificationResult.some(result => !result.verified)) {
                // define verified
                return { suspended: Array(args.credentials.length).fill(false), error: verificationResult.find(result => !result.verified)!.error || { message: 'verification: could not verify credential' }  }
            }
        }

        // if suspension options are provided, give precedence
        if (args?.suspensionOptions) {
            // validate suspension options - case: suspensionOptions.issuerDid
            if (!args.suspensionOptions.issuerDid) throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.issuerDid is required')

            // validate suspension options - case: suspensionOptions.statusListName
            if (!args.suspensionOptions.statusListName) throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListName is required')

            // validate suspension options - case: suspensionOptions.statusListIndices
            if (!args.suspensionOptions.statusListIndices || !args.suspensionOptions.statusListIndices.length || args.suspensionOptions.statusListIndices.length === 0 || !args.suspensionOptions.statusListIndices.every(index => !isNaN(+index))) throw new Error('[did-provider-cheqd]: suspension: suspensionOptions.statusListIndex is required and must be an array of indices')

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.suspensionOptions.issuerDid}?resourceName=${args.suspensionOptions.statusListName}&resourceType=StatusList2021Suspension`

            // construct credential status
            args.credentials = args.suspensionOptions.statusListIndices.map(index => ({
                '@context': [],
                issuer: args.suspensionOptions!.issuerDid,
                credentialSubject: {},
                credentialStatus: {
                    id: `${statusListCredential}#${index}`,
                    type: 'StatusList2021Entry',
                    statusPurpose: 'suspension',
                    statusListIndex: `${index}`,
                },
                issuanceDate: '',
                proof: {}
            }))
        }

        // validate args - case: credentials
        if (!args.credentials || !args.credentials.length || args.credentials.length === 0) throw new Error('[did-provider-cheqd]: suspension: credentials is required and must be an array of credentials')

        // if jwt credentials, decode them
        const credentials = await Promise.all(args.credentials.map(async credential => typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential))

        // validate args in pairs - case: statusListFile and statusList
        if (args.options?.statusListFile && args.options?.statusList) {
            throw new Error('[did-provider-cheqd]: suspension: statusListFile and statusList are mutually exclusive')
        }

        // validate args in pairs - case: statusListFile and fetchList
        if (args.options?.statusListFile && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: suspension: statusListFile and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: statusList and fetchList
        if (args.options?.statusList && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: suspension: statusList and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: publish
        if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
            throw new Error('[did-provider-cheqd]: suspension: publish requires statusListFile or statusList, if fetchList is disabled')
        }

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
                fee: args?.options?.fee
            }
        })
    }

    private async UnsuspendCredentialWithStatusList2021(args: ICheqdUnsuspendCredentialWithStatusList2021Args, context: IContext): Promise<UnsuspensionResult> {
        // verify credential, if provided and unsuspension options are not
        if (args?.credential && !args?.unsuspensionOptions) {
            const verificationResult = await context.agent.verifyCredential({
                credential: args.credential,
                policies: {
                    credentialStatus: false
                }
            } satisfies IVerifyCredentialArgs)

            // early return if verification failed
            if (!verificationResult.verified) {
                return { unsuspended: false, error: verificationResult.error }
            }
        }

        // if unsuspension options are provided, give precedence
        if (args?.unsuspensionOptions) {
            // validate unsuspension options - case: unsuspensionOptions.issuerDid
            if (!args.unsuspensionOptions.issuerDid) throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.issuerDid is required')

            // validate unsuspension options - case: unsuspensionOptions.statusListName
            if (!args.unsuspensionOptions.statusListName) throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListName is required')

            // validate unsuspension options - case: unsuspensionOptions.statusListIndex
            if (!args.unsuspensionOptions.statusListIndex) throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListIndex is required')

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.unsuspensionOptions.issuerDid}?resourceName=${args.unsuspensionOptions.statusListName}&resourceType=StatusList2021Suspension`

            // construct credential status
            args.credential = {
                '@context': [],
                issuer: args.unsuspensionOptions.issuerDid,
                credentialSubject: {},
                credentialStatus: {
                    id: `${statusListCredential}#${args.unsuspensionOptions.statusListIndex}`,
                    type: 'StatusList2021Entry',
                    statusPurpose: 'suspension',
                    statusListIndex: `${args.unsuspensionOptions.statusListIndex}`,
                },
                issuanceDate: '',
                proof: {}
            }
        }

        // validate args - case: credential
        if (!args.credential) throw new Error('[did-provider-cheqd]: unsuspension: credential is required')

        // if jwt credential, decode it
        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential

        // validate status purpose
        if (credential.credentialStatus?.statusPurpose !== 'suspension') {
            throw new Error(`[did-provider-cheqd]: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }

        // validate args in pairs - case: statusListFile and statusList
        if (args.options?.statusListFile && args.options?.statusList) {
            throw new Error('[did-provider-cheqd]: suspension: statusListFile and statusList are mutually exclusive')
        }

        // validate args in pairs - case: statusListFile and fetchList
        if (args.options?.statusListFile && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: suspension: statusListFile and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: statusList and fetchList
        if (args.options?.statusList && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: suspension: statusList and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: publish
        if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
            throw new Error('[did-provider-cheqd]: suspension: publish requires statusListFile or statusList, if fetchList is disabled')
        }

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
                fee: args?.options?.fee
            }
        })
    }

    private async UnsuspendBulkCredentialsWithStatusList2021(args: ICheqdUnsuspendBulkCredentialsWithStatusList2021Args, context: IContext): Promise<BulkUnsuspensionResult> {
        // verify credential, if provided and unsuspension options are not
        if (args?.credentials && !args?.unsuspensionOptions) {
            
            const verificationResult = await Promise.all(args.credentials.map(async (credential) => {
                return await context.agent.verifyCredential({
                    credential,
                    policies: {
                        credentialStatus: false
                    }
                } satisfies IVerifyCredentialArgs)
            }))

            // early return if verification failed for any credential
            if (verificationResult.some(result => !result.verified)) {
                // define verified
                return { unsuspended: Array(args.credentials.length).fill(false), error: verificationResult.find(result => !result.verified)!.error || { message: 'verification: could not verify credential' }  }
            }
        }

        // if unsuspension options are provided, give precedence
        if (args?.unsuspensionOptions) {
            // validate unsuspension options - case: unsuspensionOptions.issuerDid
            if (!args.unsuspensionOptions.issuerDid) throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.issuerDid is required')

            // validate unsuspension options - case: unsuspensionOptions.statusListName
            if (!args.unsuspensionOptions.statusListName) throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListName is required')

            // validate unsuspension options - case: unsuspensionOptions.statusListIndices
            if (!args.unsuspensionOptions.statusListIndices || !args.unsuspensionOptions.statusListIndices.length || args.unsuspensionOptions.statusListIndices.length === 0 || !args.unsuspensionOptions.statusListIndices.every(index => !isNaN(+index))) throw new Error('[did-provider-cheqd]: unsuspension: unsuspensionOptions.statusListIndex is required and must be an array of indices')

            // construct status list credential
            const statusListCredential = `${DefaultResolverUrl}${args.unsuspensionOptions.issuerDid}?resourceName=${args.unsuspensionOptions.statusListName}&resourceType=StatusList2021Suspension`

            // construct credential status
            args.credentials = args.unsuspensionOptions.statusListIndices.map(index => ({
                '@context': [],
                issuer: args.unsuspensionOptions!.issuerDid,
                credentialSubject: {},
                credentialStatus: {
                    id: `${statusListCredential}#${index}`,
                    type: 'StatusList2021Entry',
                    statusPurpose: 'suspension',
                    statusListIndex: `${index}`,
                },
                issuanceDate: '',
                proof: {}
            }))
        }

        // validate args - case: credentials
        if (!args.credentials || !args.credentials.length || args.credentials.length === 0) throw new Error('[did-provider-cheqd]: unsuspension: credentials is required and must be an array of credentials')

        // if jwt credentials, decode them
        const credentials = await Promise.all(args.credentials.map(async credential => typeof credential === 'string' ? await Cheqd.decodeCredentialJWT(credential) : credential))

        // validate args in pairs - case: statusListFile and statusList
        if (args.options?.statusListFile && args.options?.statusList) {
            throw new Error('[did-provider-cheqd]: unsuspension: statusListFile and statusList are mutually exclusive')
        }

        // validate args in pairs - case: statusListFile and fetchList
        if (args.options?.statusListFile && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: unsuspension: statusListFile and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: statusList and fetchList
        if (args.options?.statusList && args.options?.fetchList) {
            throw new Error('[did-provider-cheqd]: unsuspension: statusList and fetchList are mutually exclusive')
        }

        // validate args in pairs - case: publish
        if (args.options?.publish && !args.fetchList && !(args.options?.statusListFile || args.options?.statusList)) {
            throw new Error('[did-provider-cheqd]: unsuspension: publish requires statusListFile or statusList, if fetchList is disabled')
        }

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
                fee: args?.options?.fee
            }
        })
    }

    private async TransactSendTokens(args: ICheqdTransactSendTokensArgs, context: IContext): Promise<TransactionResult> {
        try {
            // delegate to provider
            const transactionResult = await this.didProvider.transactSendTokens({
                recipientAddress: args.recipientAddress,
                amount: args.amount,
                memo: args.memo,
                txBytes: args.txBytes,
            })

            // return transaction result
            return {
                successful: !transactionResult.code,
                transactionHash: transactionResult.transactionHash,
                events: transactionResult.events,
                rawLog: transactionResult.rawLog,
                txResponse: args?.returnTxResponse ? transactionResult : undefined
            } satisfies TransactionResult
        } catch (error) {
            // return error
            return {
                successful: false,
                error: error as IError
            } satisfies TransactionResult
        }
    }

    private async ObservePaymentCondition(args: ICheqdObservePaymentConditionArgs, context: IContext): Promise<ObservationResult> {
        // verify with raw unified access control condition, if any
        if (args?.unifiedAccessControlCondition) {
            // validate args - case: unifiedAccessControlCondition.chain
            if (!args.unifiedAccessControlCondition.chain || !Object.values(LitCompatibleCosmosChains).includes(args.unifiedAccessControlCondition.chain as LitCompatibleCosmosChain)) throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.chain is required and must be a valid Lit-compatible chain')

            // validate args - case: unifiedAccessControlCondition.path
            if (!args.unifiedAccessControlCondition.path) throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.path is required')

            // validate args - case: unifiedAccessControlCondition.conditionType
            if (args.unifiedAccessControlCondition.conditionType !== 'cosmos') throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.conditionType must be cosmos')

            // validate args - case: unifiedAccessControlCondition.method
            if (args.unifiedAccessControlCondition.method !== 'timelock') throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.method must be timelock')

            // validate args - case: unifiedAccessControlCondition.parameters
            if (!args.unifiedAccessControlCondition.parameters || !Array.isArray(args.unifiedAccessControlCondition.parameters) || args.unifiedAccessControlCondition.parameters.length === 0 || args.unifiedAccessControlCondition.parameters.length > 1) throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.parameters is required and must be an array of length 1 of type string content')

            // validate args - case: unifiedAccessControlCondition.returnValueTest
            if (!args.unifiedAccessControlCondition.returnValueTest || !args.unifiedAccessControlCondition.returnValueTest.comparator || !args.unifiedAccessControlCondition.returnValueTest.key || !args.unifiedAccessControlCondition.returnValueTest.value) throw new Error('[did-provider-cheqd]: observe: unifiedAccessControlCondition.returnValueTest is required')

            try {
                // define network
                const network = (function() {
                    switch (args.unifiedAccessControlCondition.chain) {
                        case LitCompatibleCosmosChains.cheqdMainnet:
                            return CheqdNetwork.Mainnet
                        case LitCompatibleCosmosChains.cheqdTestnet:
                            return CheqdNetwork.Testnet
                        default:
                            throw new Error(`[did-provider-cheqd]: observe: Unsupported chain: ${args.unifiedAccessControlCondition.chain}`)
                    }
                }())

                // get block height url
                const blockHeightUrl = function (){
                    switch (args.unifiedAccessControlCondition.parameters[0]) {
                        case 'latest':
                            return `${DefaultRESTUrls[network]}/cosmos/base/tendermint/v1beta1/blocks/latest`
                        default:
                            return `${DefaultRESTUrls[network]}/cosmos/base/tendermint/v1beta1/blocks/${args.unifiedAccessControlCondition.parameters[0]}`
                    }
                }()

                // fetch block response
                const blockHeightResponse = await (await fetch(blockHeightUrl)).json() as BlockResponse

                // get timestamp from block response
                const blockTimestamp = Date.parse(blockHeightResponse.block.header.time)

                // construct url
                const url = `${DefaultRESTUrls[network]}${args.unifiedAccessControlCondition.path}`

                // fetch relevant txs
                const txs = await (await fetch(url)).json() as ShallowTypedTxsResponse

                // skim through txs for relevant events, in which case the transaction timestamp is within the defined interval in seconds, from the block timestamp
                const meetsConditionTxIndex = txs?.tx_responses?.findIndex((tx) => {
                    // get tx timestamp
                    const txTimestamp = Date.parse(tx.timestamp)

                    // calculate diff in seconds
                    const diffInSeconds = Math.floor((blockTimestamp - txTimestamp) / 1000)

                    // return meets condition
                    switch (args.unifiedAccessControlCondition!.returnValueTest.comparator) {
                        case '<':
                            return diffInSeconds < parseInt(args.unifiedAccessControlCondition!.returnValueTest.value)
                        case '<=':
                            return diffInSeconds <= parseInt(args.unifiedAccessControlCondition!.returnValueTest.value)
                        default:
                            throw new Error(`[did-provider-cheqd]: observe: Unsupported comparator: ${args.unifiedAccessControlCondition!.returnValueTest.comparator}`)
                    }
                })

                // define meetsCondition
                const meetsCondition = (typeof meetsConditionTxIndex !== 'undefined' && meetsConditionTxIndex !== -1)

                // return observation result
                return {
                    subscribed: true,
                    meetsCondition: meetsCondition,
                    transactionHash: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].txhash : undefined,
                    events: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].events : undefined,
                    rawLog: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].raw_log : undefined,
                    txResponse: meetsCondition ? (args?.returnTxResponse ? txs!.tx_responses[meetsConditionTxIndex] : undefined) : undefined
                } satisfies ObservationResult
            } catch (error) {
                // return error
                return {
                    subscribed: false,
                    meetsCondition: false,
                    error: error as IError
                } satisfies ObservationResult
            }
        }

        // validate access control conditions components - case: recipientAddress
        if (!args.recipientAddress) {
            throw new Error('[did-provider-cheqd]: observation: recipientAddress is required')
        }

        // validate access control conditions components - case: amount
        if (!args.amount || !args.amount.amount || !args.amount.denom || args.amount.denom !== 'ncheq') {
            throw new Error('[did-provider-cheqd]: observation: amount is required, and must be an object with amount and denom valid string properties, amongst which denom must be `ncheq`')
        }

        // validate access control conditions components - case: intervalInSeconds
        if (!args.intervalInSeconds) {
            throw new Error('[did-provider-cheqd]: observation: intervalInSeconds is required')
        }

        // validate access control conditions components - case: comparator
        if (!args.comparator || (args.comparator !== '<' && args.comparator !== '<=')) {
            throw new Error('[did-provider-cheqd]: observation: comparator is required and must be either `<` or `<=`')
        }

        // validate access control conditions components - case: network
        if (!args.network) {
            throw new Error('[did-provider-cheqd]: observation: network is required')
        }

        // define block height, if not provided
        args.blockHeight ||= 'latest'

        try {
            // get block height url
            const blockHeightUrl = function (){
                switch (args.blockHeight) {
                    case 'latest':
                        return `${DefaultRESTUrls[args.network]}/cosmos/base/tendermint/v1beta1/blocks/latest`
                    default:
                        return `${DefaultRESTUrls[args.network]}/cosmos/base/tendermint/v1beta1/blocks/${args.blockHeight}`
                }
            }()

            // fetch block response
            const blockHeightResponse = await (await fetch(blockHeightUrl)).json() as BlockResponse

            // get timestamp from block response
            const blockTimestamp = Date.parse(blockHeightResponse.block.header.time)

            // otherwise, construct url, as per components
            const url = `${DefaultRESTUrls[args.network]}/cosmos/tx/v1beta1/txs?events=transfer.recipient='${args.recipientAddress}'&events=transfer.amount='${args.amount.amount}${args.amount.denom}'&order_by=2&pagination.limit=1`

            // fetch relevant txs
            const txs = await (await fetch(url)).json() as ShallowTypedTxsResponse

            // skim through txs for relevant events, in which case the transaction timestamp is within the defined interval in seconds, from the block timestamp
            const meetsConditionTxIndex = txs?.tx_responses?.findIndex((tx) => {
                // get tx timestamp
                const txTimestamp = Date.parse(tx.timestamp)

                // calculate diff in seconds
                const diffInSeconds = Math.floor((blockTimestamp - txTimestamp) / 1000)

                // return meets condition
                switch (args.comparator) {
                    case '<':
                        return diffInSeconds < args.intervalInSeconds!
                    case '<=':
                        return diffInSeconds <= args.intervalInSeconds!
                    default:
                        throw new Error(`[did-provider-cheqd]: observe: Unsupported comparator: ${args.unifiedAccessControlCondition!.returnValueTest.comparator}`)
                }
            })

            // define meetsCondition
            const meetsCondition = (typeof meetsConditionTxIndex !== 'undefined' && meetsConditionTxIndex !== -1)

            // return observation result
            return {
                subscribed: true,
                meetsCondition: meetsCondition,
                transactionHash: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].txhash : undefined,
                events: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].events : undefined,
                rawLog: meetsCondition ? txs!.tx_responses[meetsConditionTxIndex].raw_log : undefined,
                txResponse: meetsCondition ? (args?.returnTxResponse ? txs!.tx_responses[meetsConditionTxIndex] : undefined) : undefined
            } satisfies ObservationResult
        } catch (error) {
            // return error
            return {
                subscribed: false,
                meetsCondition: false,
                error: error as IError
            } satisfies ObservationResult
        }
    }

    static async revokeCredential(credential: VerifiableCredential, options?: ICheqdStatusList2021Options): Promise<RevocationResult> {
        try {
            // validate status purpose
            if (credential?.credentialStatus?.statusPurpose !== 'revocation') throw new Error('[did-provider-cheqd]: revocation: Invalid status purpose')

            // fetch status list 2021
            const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Revocation

            // early return, if encrypted and no decryption key provided
            if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: revocation: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted)
                        return publishedList.metadata.encoding === 'base64url'
                            ? publishedList.StatusList2021.encodedList
                            : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // otherwise, decrypt and return raw bitstring
                    const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // transcode to base64url, if needed
                    const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!publishedList.metadata.encrypted) {
                            // construct encoded status list
                            const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                            // validate against published list
                            if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021')

                            // return encoded
                            return encoded
                        }

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                        // validate against published list
                        if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021')

                        // return decrypted
                        return decrypted
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: revocation: statusListInlineBitstring is required, if statusListFile is not provided')

                    // validate against published list
                    if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: revocation: statusListInlineBitstring does not match published status list 2021')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // early exit, if credential is already revoked
            if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { revoked: false }

            // update revocation status
            statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true)

            // set in-memory status list ref
            const bitstring = await statusList.encode() as Bitstring

            // cast top-level args
            const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusList2021Args

            // write status list 2021 to file, if provided
            if (topArgs?.writeToFile) {
                await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile)
            }

            // publish status list 2021, if provided
            const published = topArgs?.publish
                ? (await async function () {
                    // fetch status list 2021 metadata
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credential)

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: revocation: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)')
                            }

                            // validate paymentConditions, if provided
                            if (topArgs?.paymentConditions) {
                                if (!topArgs?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
                                }
    
                                if (!topArgs?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                                    throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
                                }
    
                                if (!topArgs?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
                                }
                            }

                            // validate dkgOptions
                            if (!topArgs?.dkgOptions || !topArgs?.dkgOptions?.chain || !topArgs?.dkgOptions?.network) {
                                throw new Error('[did-provider-cheqd]: dkgOptions is required')
                            }

                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: topArgs?.dkgOptions?.chain,
                                litNetwork: topArgs?.dkgOptions?.network
                            })

                            // construct access control conditions and payment conditions tuple
                            const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
                                ? (await (async function () {
                                    // define payment conditions, give precedence to top-level args
                                    const paymentConditions = topArgs?.paymentConditions || publishedList.metadata.paymentConditions!

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight,
                                                        topArgs?.dkgOptions?.chain
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))
                                : (await (async function () {
                                    // validate paymentConditions
                                    if (!topArgs?.paymentConditions) {
                                        throw new Error('[did-provider-cheqd]: paymentConditions is required')
                                    }

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(topArgs.paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        topArgs.paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))

                            // encrypt bitstring
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditionsTuple[0], true)

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: await blobToHexString(encryptedString),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encrypted: true,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encryptedSymmetricKey,
                                    paymentConditions: unifiedAccessControlConditionsTuple[1]
                                }
                            } satisfies StatusList2021Revocation

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: revocation: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)')
                            }

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: publishedList.metadata.encoding === 'base64url' ? bitstring : toString(fromString(bitstring, 'base64url'), options!.publishOptions.statusListEncoding as DefaultStatusList2021Encoding),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encrypted: false,
                                }
                            } satisfies StatusList2021Revocation

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                undefined
                            ]
                        }())

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: revocation: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                revoked: true,
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? await Cheqd.fetchStatusList2021(credential) as StatusList2021Revocation : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credential) : undefined
            } satisfies RevocationResult
        } catch (error) {
            // silent fail + early exit
            console.error(error)

            return { revoked: false, error: error as IError } satisfies RevocationResult
        }
    }

    static async revokeCredentials(credentials: VerifiableCredential[], options?: ICheqdStatusList2021Options): Promise<BulkRevocationResult> {
        // validate credentials - case: empty
        if (!credentials.length || credentials.length === 0) throw new Error('[did-provider-cheqd]: revocation: No credentials provided')

        // validate credentials - case: consistent issuer
        if (credentials.map((credential) => {
            return ((credential.issuer as { id: string }).id)
                ? (credential.issuer as { id: string }).id
                : credential.issuer as string
        }).filter((value, _, self) => value && value !== self[0]).length > 0) throw new Error('[did-provider-cheqd]: revocation: Credentials must be issued by the same issuer')

        // validate credentials - case: status list index
        if (credentials.map((credential) => credential.credentialStatus!.statusListIndex).filter((value, index, self) => self.indexOf(value) !== index).length > 0) throw new Error('[did-provider-cheqd]: revocation: Credentials must have unique status list index')

        // validate credentials - case: status purpose
        if (!credentials.every((credential) => credential.credentialStatus?.statusPurpose === 'revocation')) throw new Error('[did-provider-cheqd]: revocation: Invalid status purpose')

        // validate credentials - case: status list id
        const remote = credentials[0].credentialStatus?.id
            ? (credentials[0].credentialStatus as { id: string }).id.split('#')[0]
            : (function(){
                throw new Error('[did-provider-cheqd]: revocation: Invalid status list id')
            }())

        // validate credentials - case: status list id format
        if (!RemoteListPattern.test(remote)) throw new Error('[did-provider-cheqd]: revocation: Invalid status list id format: expected: https://<optional_subdomain>.<sld>.<tld>/1.0/identifiers/<did:cheqd:<namespace>:<method_specific_id>>?resourceName=<resource_name>&resourceType=<resource_type>')

        if (!credentials.every((credential) => {
            return (credential.credentialStatus as { id: string }).id.split('#')[0] === remote
        })) throw new Error('[did-provider-cheqd]: revocation: Credentials must belong to the same status list')

        // validate credentials - case: status list type
        if (!credentials.every((credential) => credential.credentialStatus?.type === 'StatusList2021Entry')) throw new Error('[did-provider-cheqd]: revocation: Invalid status list type')

        try {
            // fetch status list 2021
            const publishedList = (await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Revocation

            // early return, if encrypted and no decryption key provided
            if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: revocation: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted)
                        return publishedList.metadata.encoding === 'base64url'
                            ? publishedList.StatusList2021.encodedList
                            : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // otherwise, decrypt and return raw bitstring
                    const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // transcode to base64url, if needed
                    const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!publishedList.metadata.encrypted) {
                            // construct encoded status list
                            const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                            // validate against published list
                            if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021')

                            // return encoded
                            return encoded
                        }

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                        // validate against published list
                        if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: revocation: statusListFile does not match published status list 2021')

                        // return decrypted
                        return decrypted
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: revocation: statusListInlineBitstring is required, if statusListFile is not provided')

                    // validate against published list
                    if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: revocation: statusListInlineBitstring does not match published status list 2021')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // initiate bulk revocation
            const revoked = await Promise.allSettled(credentials.map((credential) => {
                return async function () {
                    // early return, if no credential status
                    if (!credential.credentialStatus) return { revoked: false }

                    // early exit, if credential is already revoked
                    if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { revoked: false }

                    // update revocation status
                    statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true)

                    // return revocation status
                    return { revoked: true }
                }()
            })) satisfies PromiseSettledResult<RevocationResult>[]

            // revert bulk ops, if some failed
            if (revoked.some((result) => result.status === 'fulfilled' && !result.value.revoked )) 
                throw new Error(`[did-provider-cheqd]: revocation: Bulk revocation failed: already revoked credentials in revocation bundle: raw log: ${JSON.stringify(revoked.map((result) => ({ revoked: result.status === 'fulfilled' ? result.value.revoked : false })))}`)

            // set in-memory status list ref
            const bitstring = await statusList.encode() as Bitstring

            // cast top-level args
            const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusList2021Args

            // write status list 2021 to file, if provided
            if (topArgs?.writeToFile) {
                await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile)
            }

            // publish status list 2021, if provided
            const published = topArgs?.publish
                ? (await async function () {
                    // fetch status list 2021 metadata
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credentials[0])

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: revocation: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)')
                            }

                            // validate paymentConditions, if provided
                            if (topArgs?.paymentConditions) {
                                if (!topArgs?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                                    throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
                                }
                            }

                            // validate dkgOptions
                            if (!topArgs?.dkgOptions || !topArgs?.dkgOptions?.chain || !topArgs?.dkgOptions?.network) {
                                throw new Error('[did-provider-cheqd]: dkgOptions is required')
                            }

                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: topArgs?.dkgOptions?.chain,
                                litNetwork: topArgs?.dkgOptions?.network
                            })

                            // construct access control conditions and payment conditions tuple
                            const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
                                ? (await (async function () {
                                    // define payment conditions, give precedence to top-level args
                                    const paymentConditions = topArgs?.paymentConditions || publishedList.metadata.paymentConditions!

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight,
                                                        topArgs?.dkgOptions?.chain
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))
                                : (await (async function () {
                                    // validate paymentConditions
                                    if (!topArgs?.paymentConditions) {
                                        throw new Error('[did-provider-cheqd]: paymentConditions is required')
                                    }

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(topArgs.paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        topArgs.paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))

                            // encrypt bitstring
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditionsTuple[0], true)

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: await blobToHexString(encryptedString),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encrypted: true,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encryptedSymmetricKey,
                                    paymentConditions: unifiedAccessControlConditionsTuple[1]
                                }
                            } satisfies StatusList2021Revocation

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: revocation: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: revocation: Invalid status list validUntil (must be after validFrom)')
                            }

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: publishedList.metadata.encoding === 'base64url' ? bitstring : toString(fromString(bitstring, 'base64url'), options!.publishOptions.statusListEncoding as DefaultStatusList2021Encoding),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encrypted: false,
                                }
                            } satisfies StatusList2021Revocation

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                undefined
                            ]
                        }())

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: revocation: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                revoked: revoked.map((result) => result.status === 'fulfilled' ? result.value.revoked : false),
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? await Cheqd.fetchStatusList2021(credentials[0]) as StatusList2021Revocation : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credentials[0]) : undefined
            } satisfies BulkRevocationResult
        } catch (error) {
            // silent fail + early exit
            console.error(error)

            return { revoked: [], error: error as IError } satisfies BulkRevocationResult
        }
    }

    static async suspendCredential(credential: VerifiableCredential, options?: ICheqdStatusList2021Options): Promise<SuspensionResult> {
        try {
            // validate status purpose
            if (credential?.credentialStatus?.statusPurpose !== 'suspension') throw new Error('[did-provider-cheqd]: suspension: Invalid status purpose')

            // fetch status list 2021
            const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension

            // early return, if encrypted and no decryption key provided
            if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: suspension: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted)
                        return publishedList.metadata.encoding === 'base64url'
                            ? publishedList.StatusList2021.encodedList
                            : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // otherwise, decrypt and return raw bitstring
                    const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // transcode to base64url, if needed
                    const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!publishedList.metadata.encrypted) {
                            // construct encoded status list
                            const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                            // validate against published list
                            if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021')

                            // return encoded
                            return encoded
                        }

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                        // validate against published list
                        if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021')

                        // return decrypted
                        return decrypted
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: suspension: statusListInlineBitstring is required, if statusListFile is not provided')

                    // validate against published list
                    if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: suspension: statusListInlineBitstring does not match published status list 2021')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // early exit, if already suspended
            if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { suspended: true } satisfies SuspensionResult

            // update suspension status
            statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true)

            // set in-memory status list ref
            const bitstring = await statusList.encode() as Bitstring

            // cast top-level args
            const topArgs = options?.topArgs as ICheqdSuspendCredentialWithStatusList2021Args

            // write status list 2021 to file, if provided
            if (topArgs?.writeToFile) {
                await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile)
            }

            // publish status list 2021, if provided
            const published = topArgs?.publish
                ? (await async function () {
                    // fetch status list 2021 metadata
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credential)

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: suspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // validate paymentConditions, if provided
                            if (topArgs?.paymentConditions) {
                                if (!topArgs?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                                    throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
                                }
                            }

                            // validate dkgOptions
                            if (!topArgs?.dkgOptions || !topArgs?.dkgOptions?.chain || !topArgs?.dkgOptions?.network) {
                                throw new Error('[did-provider-cheqd]: dkgOptions is required')
                            }

                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: topArgs?.dkgOptions?.chain,
                                litNetwork: topArgs?.dkgOptions?.network
                            })

                            // construct access control conditions and payment conditions tuple
                            const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
                                ? (await (async function () {
                                    // define payment conditions, give precedence to top-level args
                                    const paymentConditions = topArgs?.paymentConditions || publishedList.metadata.paymentConditions!

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight,
                                                        topArgs?.dkgOptions?.chain
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))
                                : (await (async function () {
                                    // validate paymentConditions
                                    if (!topArgs?.paymentConditions) {
                                        throw new Error('[did-provider-cheqd]: paymentConditions is required')
                                    }

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(topArgs.paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        topArgs.paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))

                            // encrypt bitstring
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditionsTuple[0], true)

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: await blobToHexString(encryptedString),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encrypted: true,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encryptedSymmetricKey,
                                    paymentConditions: unifiedAccessControlConditionsTuple[1]
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: suspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: publishedList.metadata.encoding === 'base64url' ? bitstring : toString(fromString(bitstring, 'base64url'), options!.publishOptions.statusListEncoding as DefaultStatusList2021Encoding),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encrypted: false,
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                undefined
                            ]
                        }())

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: suspension: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                suspended: true,
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? await Cheqd.fetchStatusList2021(credential) as StatusList2021Suspension : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credential) : undefined
            } satisfies SuspensionResult
        } catch (error) {
            // silent fail + early exit
            console.error(error)

            return { suspended: false, error: error as IError } satisfies SuspensionResult
        }
    }

    static async suspendCredentials(credentials: VerifiableCredential[], options?: ICheqdStatusList2021Options): Promise<BulkSuspensionResult> {
        // validate credentials - case: empty
        if (!credentials.length || credentials.length === 0) throw new Error('[did-provider-cheqd]: suspension: No credentials provided')

        // validate credentials - case: consistent issuer
        if (credentials.map((credential) => {
            return ((credential.issuer as { id: string }).id)
                ? (credential.issuer as { id: string }).id
                : credential.issuer as string
        }).filter((value, _, self) => value && value !== self[0]).length > 0) throw new Error('[did-provider-cheqd]: suspension: Credentials must be issued by the same issuer')

        // validate credentials - case: status list index
        if (credentials.map((credential) => credential.credentialStatus!.statusListIndex).filter((value, index, self) => self.indexOf(value) !== index).length > 0) throw new Error('[did-provider-cheqd]: suspension: Credentials must have unique status list index')

        // validate credentials - case: status purpose
        if (!credentials.every((credential) => credential.credentialStatus?.statusPurpose === 'suspension')) throw new Error('[did-provider-cheqd]: suspension: Invalid status purpose')

        // validate credentials - case: status list id
        const remote = credentials[0].credentialStatus?.id
            ? (credentials[0].credentialStatus as { id: string }).id.split('#')[0]
            : (function(){
                throw new Error('[did-provider-cheqd]: suspension: Invalid status list id')
            }())

        // validate credentials - case: status list id format
        if (!RemoteListPattern.test(remote)) throw new Error('[did-provider-cheqd]: suspension: Invalid status list id format: expected: https://<optional_subdomain>.<sld>.<tld>/1.0/identifiers/<did:cheqd:<namespace>:<method_specific_id>>?resourceName=<resource_name>&resourceType=<resource_type>')

        if (!credentials.every((credential) => {
            return (credential.credentialStatus as { id: string }).id.split('#')[0] === remote
        })) throw new Error('[did-provider-cheqd]: suspension: Credentials must belong to the same status list')

        // validate credentials - case: status list type
        if (!credentials.every((credential) => credential.credentialStatus?.type === 'StatusList2021Entry')) throw new Error('[did-provider-cheqd]: suspension: Invalid status list type')

        try {
            // fetch status list 2021
            const publishedList = (await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Suspension

            // early return, if encrypted and no decryption key provided
            if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: suspension: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted)
                        return publishedList.metadata.encoding === 'base64url'
                            ? publishedList.StatusList2021.encodedList
                            : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // otherwise, decrypt and return raw bitstring
                    const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // transcode to base64url, if needed
                    const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!publishedList.metadata.encrypted) {
                            // construct encoded status list
                            const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                            // validate against published list
                            if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021')

                            // return encoded
                            return encoded
                        }

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                        // validate against published list
                        if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: suspension: statusListFile does not match published status list 2021')

                        // return decrypted
                        return decrypted
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: suspension: statusListInlineBitstring is required, if statusListFile is not provided')

                    // validate against published list
                    if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: suspension: statusListInlineBitstring does not match published status list 2021')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // initiate bulk suspension
            const suspended = await Promise.allSettled(credentials.map((credential) => {
                return async function () {
                    // early return, if no credential status
                    if (!credential.credentialStatus) return { suspended: false }

                    // early exit, if credential is already suspended
                    if (statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { suspended: false }

                    // update suspension status
                    statusList.setStatus(Number(credential.credentialStatus.statusListIndex), true)

                    // return suspension status
                    return { suspended: true }
                }()
            })) satisfies PromiseSettledResult<SuspensionResult>[]

            // revert bulk ops, if some failed
            if (suspended.some((result) => result.status === 'fulfilled' && !result.value.suspended )) 
                throw new Error(`[did-provider-cheqd]: suspension: Bulk suspension failed: already suspended credentials in suspension bundle: raw log: ${JSON.stringify(suspended.map((result) => ({ suspended: result.status === 'fulfilled' ? result.value.suspended : false })))}`)

            // set in-memory status list ref
            const bitstring = await statusList.encode() as Bitstring

            // cast top-level args
            const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusList2021Args

            // write status list 2021 to file, if provided
            if (topArgs?.writeToFile) {
                await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile)
            }

            // publish status list 2021, if provided
            const published = topArgs?.publish
                ? (await async function () {
                    // fetch status list 2021 metadata
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credentials[0])

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: suspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // validate paymentConditions, if provided
                            if (topArgs?.paymentConditions) {
                                if (!topArgs?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                                    throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
                                }
                            }

                            // validate dkgOptions
                            if (!topArgs?.dkgOptions || !topArgs?.dkgOptions?.chain || !topArgs?.dkgOptions?.network) {
                                throw new Error('[did-provider-cheqd]: dkgOptions is required')
                            }

                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: topArgs?.dkgOptions?.chain,
                                litNetwork: topArgs?.dkgOptions?.network
                            })

                            // construct access control conditions and payment conditions tuple
                            const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
                                ? (await (async function () {
                                    // define payment conditions, give precedence to top-level args
                                    const paymentConditions = topArgs?.paymentConditions || publishedList.metadata.paymentConditions!

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight,
                                                        topArgs?.dkgOptions?.chain
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))
                                : (await (async function () {
                                    // validate paymentConditions
                                    if (!topArgs?.paymentConditions) {
                                        throw new Error('[did-provider-cheqd]: paymentConditions is required')
                                    }

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(topArgs.paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        topArgs.paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))

                            // encrypt bitstring
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditionsTuple[0], true)

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: await blobToHexString(encryptedString),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encrypted: true,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encryptedSymmetricKey,
                                    paymentConditions: unifiedAccessControlConditionsTuple[1]
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: suspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: suspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: publishedList.metadata.encoding === 'base64url' ? bitstring : toString(fromString(bitstring, 'base64url'), options!.publishOptions.statusListEncoding as DefaultStatusList2021Encoding),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encrypted: false,
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                undefined
                            ]
                        }())

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: suspension: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                suspended: suspended.map((result) => result.status === 'fulfilled' ? result.value.suspended : false),
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? await Cheqd.fetchStatusList2021(credentials[0]) as StatusList2021Suspension : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credentials[0]) : undefined
            } satisfies BulkSuspensionResult
        } catch (error) {
            // silent fail + early exit
            console.error(error)
            return { suspended: [], error: error as IError } satisfies BulkSuspensionResult
        }
    }

    static async unsuspendCredential(credential: VerifiableCredential, options?: ICheqdStatusList2021Options): Promise<UnsuspensionResult> {
        try {
            // validate status purpose
            if (credential?.credentialStatus?.statusPurpose !== 'suspension') throw new Error('[did-provider-cheqd]: unsuspension: Invalid status purpose')

            // fetch status list 2021
            const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension

            // early return, if encrypted and no decryption key provided
            if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: unsuspension: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted)
                        return publishedList.metadata.encoding === 'base64url'
                            ? publishedList.StatusList2021.encodedList
                            : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // otherwise, decrypt and return raw bitstring
                    const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // transcode to base64url, if needed
                    const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!publishedList.metadata.encrypted) {
                            // construct encoded status list
                            const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                            // validate against published list
                            if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021')

                            // return encoded
                            return encoded
                        }

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                        // validate against published list
                        if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021')

                        // return decrypted
                        return decrypted
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: unsuspension: statusListInlineBitstring is required, if statusListFile is not provided')

                    // validate against published list
                    if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: unsuspension: statusListInlineBitstring does not match published status list 2021')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // early exit, if already unsuspended
            if (!statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { unsuspended: true } satisfies UnsuspensionResult

            // update suspension status
            statusList.setStatus(Number(credential.credentialStatus.statusListIndex), false)

            // set in-memory status list ref
            const bitstring = await statusList.encode() as Bitstring

            // cast top-level args
            const topArgs = options?.topArgs as ICheqdSuspendCredentialWithStatusList2021Args

            // write status list 2021 to file, if provided
            if (topArgs?.writeToFile) {
                await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile)
            }

            // publish status list 2021, if provided
            const published = topArgs?.publish
                ? (await async function () {
                    // fetch status list 2021 metadata
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credential)

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // validate paymentConditions, if provided
                            if (topArgs?.paymentConditions) {
                                if (!topArgs?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                                    throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
                                }
                            }

                            // validate dkgOptions
                            if (!topArgs?.dkgOptions || !topArgs?.dkgOptions?.chain || !topArgs?.dkgOptions?.network) {
                                throw new Error('[did-provider-cheqd]: dkgOptions is required')
                            }

                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: topArgs?.dkgOptions?.chain,
                                litNetwork: topArgs?.dkgOptions?.network
                            })

                            // construct access control conditions and payment conditions tuple
                            const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
                                ? (await (async function () {
                                    // define payment conditions, give precedence to top-level args
                                    const paymentConditions = topArgs?.paymentConditions || publishedList.metadata.paymentConditions!

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight,
                                                        topArgs?.dkgOptions?.chain
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))
                                : (await (async function () {
                                    // validate paymentConditions
                                    if (!topArgs?.paymentConditions) {
                                        throw new Error('[did-provider-cheqd]: paymentConditions is required')
                                    }

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(topArgs.paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        topArgs.paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))

                            // encrypt bitstring
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditionsTuple[0], true)

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: await blobToHexString(encryptedString),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encrypted: true,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encryptedSymmetricKey,
                                    paymentConditions: unifiedAccessControlConditionsTuple[1]
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: publishedList.metadata.encoding === 'base64url' ? bitstring : toString(fromString(bitstring, 'base64url'), options!.publishOptions.statusListEncoding as DefaultStatusList2021Encoding),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encrypted: false,
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                undefined
                            ]
                        }())

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: unsuspension: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                unsuspended: true,
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? await Cheqd.fetchStatusList2021(credential) as StatusList2021Suspension : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credential) : undefined
            } satisfies UnsuspensionResult
        } catch (error) {
            // silent fail + early exit
            console.error(error)

            return { unsuspended: false, error: error as IError } satisfies UnsuspensionResult
        }
    }

    static async unsuspendCredentials(credentials: VerifiableCredential[], options?: ICheqdStatusList2021Options): Promise<BulkUnsuspensionResult> {
        // validate credentials - case: empty
        if (!credentials.length || credentials.length === 0) throw new Error('[did-provider-cheqd]: unsuspension: No credentials provided')

        // validate credentials - case: consistent issuer
        if (credentials.map((credential) => {
            return ((credential.issuer as { id: string }).id)
                ? (credential.issuer as { id: string }).id
                : credential.issuer as string
        }).filter((value, _, self) => value && value !== self[0]).length > 0) throw new Error('[did-provider-cheqd]: unsuspension: Credentials must be issued by the same issuer')

        // validate credentials - case: status list index
        if (credentials.map((credential) => credential.credentialStatus!.statusListIndex).filter((value, index, self) => self.indexOf(value) !== index).length > 0) throw new Error('[did-provider-cheqd]: unsuspension: Credentials must have unique status list index')

        // validate credentials - case: status purpose
        if (!credentials.every((credential) => credential.credentialStatus?.statusPurpose === 'suspension')) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status purpose')

        // validate credentials - case: status list id
        const remote = credentials[0].credentialStatus?.id
            ? (credentials[0].credentialStatus as { id: string }).id.split('#')[0]
            : (function(){
                throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list id')
            }())

        // validate credentials - case: status list id format
        if (!RemoteListPattern.test(remote)) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list id format: expected: https://<optional_subdomain>.<sld>.<tld>/1.0/identifiers/<did:cheqd:<namespace>:<method_specific_id>>?resourceName=<resource_name>&resourceType=<resource_type>')

        if (!credentials.every((credential) => {
            return (credential.credentialStatus as { id: string }).id.split('#')[0] === remote
        })) throw new Error('[did-provider-cheqd]: unsuspension: Credentials must belong to the same status list')

        // validate credentials - case: status list type
        if (!credentials.every((credential) => credential.credentialStatus?.type === 'StatusList2021Entry')) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list type')

        try {
            // fetch status list 2021
            const publishedList = (await Cheqd.fetchStatusList2021(credentials[0])) as StatusList2021Suspension

            // early return, if encrypted and no decryption key provided
            if (publishedList.metadata.encrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: unsuspension: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted)
                        return publishedList.metadata.encoding === 'base64url'
                            ? publishedList.StatusList2021.encodedList
                            : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // otherwise, decrypt and return raw bitstring
                    const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // transcode to base64url, if needed
                    const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!publishedList.metadata.encrypted) {
                            // construct encoded status list
                            const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                            // validate against published list
                            if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021')

                            // return encoded
                            return encoded
                        }

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                        // validate against published list
                        if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: unsuspension: statusListFile does not match published status list 2021')

                        // return decrypted
                        return decrypted
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: unsuspension: statusListInlineBitstring is required, if statusListFile is not provided')

                    // validate against published list
                    if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: unsuspension: statusListInlineBitstring does not match published status list 2021')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // initiate bulk unsuspension
            const unsuspended = await Promise.allSettled(credentials.map((credential) => {
                return async function () {
                    // early return, if no credential status
                    if (!credential.credentialStatus) return { unsuspended: false }

                    // early exit, if credential is already unsuspended
                    if (!statusList.getStatus(Number(credential.credentialStatus.statusListIndex))) return { unsuspended: true }

                    // update unsuspension status
                    statusList.setStatus(Number(credential.credentialStatus.statusListIndex), false)

                    // return unsuspension status
                    return { unsuspended: true }
                }()
            })) satisfies PromiseSettledResult<UnsuspensionResult>[]

            // revert bulk ops, if some failed
            if (unsuspended.some((result) => result.status === 'fulfilled' && !result.value.unsuspended )) 
                throw new Error(`[did-provider-cheqd]: unsuspension: Bulk unsuspension failed: already unsuspended credentials in unsuspension bundle: raw log: ${JSON.stringify(unsuspended.map((result) => ({ unsuspended: result.status === 'fulfilled' ? result.value.unsuspended : false })))}`)

            // set in-memory status list ref
            const bitstring = await statusList.encode() as Bitstring

            // cast top-level args
            const topArgs = options?.topArgs as ICheqdRevokeCredentialWithStatusList2021Args

            // write status list 2021 to file, if provided
            if (topArgs?.writeToFile) {
                await Cheqd.writeFile(fromString(bitstring, 'base64url'), options?.statusListFile)
            }

            // publish status list 2021, if provided
            const published = topArgs?.publish
                ? (await async function () {
                    // fetch status list 2021 metadata
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credentials[0])

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // validate paymentConditions, if provided
                            if (topArgs?.paymentConditions) {
                                if (!topArgs?.paymentConditions?.every((condition) => condition.feePaymentAddress && condition.feePaymentAmount && condition.intervalInSeconds)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must contain feePaymentAddress and feeAmount and intervalInSeconds')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => typeof condition.feePaymentAddress === 'string' && typeof condition.feePaymentAmount === 'string' && typeof condition.intervalInSeconds === 'number')) {
                                    throw new Error('[did-provider-cheqd]: feePaymentAddress and feePaymentAmount must be string and intervalInSeconds must be number')
                                }

                                if (!topArgs?.paymentConditions?.every((condition) => condition.type === AccessControlConditionTypes.timelockPayment)) {
                                    throw new Error('[did-provider-cheqd]: paymentConditions must be of type timelockPayment')
                                }
                            }

                            // validate dkgOptions
                            if (!topArgs?.dkgOptions || !topArgs?.dkgOptions?.chain || !topArgs?.dkgOptions?.network) {
                                throw new Error('[did-provider-cheqd]: dkgOptions is required')
                            }

                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: topArgs?.dkgOptions?.chain,
                                litNetwork: topArgs?.dkgOptions?.network
                            })

                            // construct access control conditions and payment conditions tuple
                            const unifiedAccessControlConditionsTuple = publishedList.metadata.encrypted
                                ? (await (async function () {
                                    // define payment conditions, give precedence to top-level args
                                    const paymentConditions = topArgs?.paymentConditions || publishedList.metadata.paymentConditions!

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight,
                                                        topArgs?.dkgOptions?.chain
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))
                                : (await (async function () {
                                    // validate paymentConditions
                                    if (!topArgs?.paymentConditions) {
                                        throw new Error('[did-provider-cheqd]: paymentConditions is required')
                                    }

                                    // return access control conditions and payment conditions tuple
                                    return [
                                        await Promise.all(topArgs.paymentConditions.map(async (condition) => {
                                            switch (condition.type) {
                                                case AccessControlConditionTypes.timelockPayment:
                                                    return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                                            key: '$.tx_responses.*.timestamp',
                                                            comparator: '<=',
                                                            value: `${condition.intervalInSeconds}`,
                                                        },
                                                        condition.feePaymentAmount,
                                                        condition.feePaymentAddress,
                                                        condition?.blockHeight
                                                    )
                                                default:
                                                    throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                                            }
                                        })),
                                        topArgs.paymentConditions
                                    ] satisfies [CosmosAccessControlCondition[], PaymentCondition[]]
                                }()))

                            // encrypt bitstring
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, unifiedAccessControlConditionsTuple[0], true)

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: await blobToHexString(encryptedString),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encrypted: true,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encryptedSymmetricKey,
                                    paymentConditions: unifiedAccessControlConditionsTuple[1]
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : (await async function () {
                            // validate encoding, if provided
                            if (options?.publishOptions?.statusListEncoding && !Object.values(DefaultStatusList2021Encodings).includes(options?.publishOptions?.statusListEncoding)) {
                                throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list encoding')
                            }

                            // validate validUntil, if provided
                            if (options?.publishOptions?.statusListValidUntil) {
                                // validate validUntil as string
                                if (typeof options?.publishOptions?.statusListValidUntil !== 'string') throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be string)')

                                // validate validUntil as date
                                if (isNaN(Date.parse(options?.publishOptions?.statusListValidUntil))) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be date)')

                                // validate validUntil as future date
                                if (new Date(options?.publishOptions?.statusListValidUntil) < new Date()) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be future date)')

                                // validate validUntil towards validFrom
                                if (new Date(options?.publishOptions?.statusListValidUntil) <= new Date(publishedList.StatusList2021.validFrom)) throw new Error('[did-provider-cheqd]: unsuspension: Invalid status list validUntil (must be after validFrom)')
                            }

                            // define status list content
                            const content = {
                                StatusList2021: {
                                    statusPurpose: publishedList.StatusList2021.statusPurpose,
                                    encodedList: publishedList.metadata.encoding === 'base64url' ? bitstring : toString(fromString(bitstring, 'base64url'), options!.publishOptions.statusListEncoding as DefaultStatusList2021Encoding),
                                    validFrom: publishedList.StatusList2021.validFrom,
                                    validUntil: options?.publishOptions?.statusListValidUntil || publishedList.StatusList2021.validUntil
                                },
                                metadata: {
                                    type: publishedList.metadata.type,
                                    encoding: (options?.publishOptions?.statusListEncoding as DefaultStatusList2021Encoding | undefined) || publishedList.metadata.encoding,
                                    encrypted: false,
                                }
                            } satisfies StatusList2021Suspension

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(fromString(JSON.stringify(content), 'utf-8'), statusListMetadata, options?.publishOptions),
                                undefined
                            ]
                        }())

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: unsuspension: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                unsuspended: unsuspended.map((result) => result.status === 'fulfilled' ? result.value.unsuspended : false),
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? await Cheqd.fetchStatusList2021(credentials[0]) as StatusList2021Suspension : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credentials[0]) : undefined
            } satisfies BulkUnsuspensionResult
        } catch (error) {
            // silent fail + early exit
            console.error(error)

            return { unsuspended: [], error: error as IError } satisfies BulkUnsuspensionResult
        }
    }

    static async checkRevoked(credential: VerifiableCredential, options: ICheqdStatusList2021Options = { fetchList: true }): Promise<boolean> {
        // validate status purpose
        if (credential.credentialStatus?.statusPurpose !== 'revocation') {
            throw new Error(`[did-provider-cheqd]: check: revocation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }

        // fetch status list 2021
        const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Revocation

        // fetch status list 2021 inscribed in credential
        const statusList2021 = options?.topArgs?.fetchList
            ? (await async function () {
                // if not encrypted, return bitstring
                if (!publishedList.metadata.encrypted)
                    return publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                // otherwise, decrypt and return raw bitstring
                const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                // instantiate dkg-threshold client, in which case lit-protocol is used
                const lit = await LitProtocol.create({
                    chain: options?.topArgs?.dkgOptions?.chain,
                    litNetwork: options?.topArgs?.dkgOptions?.network
                })

                // construct access control conditions
                const unifiedAccessControlConditions = await Promise.all(publishedList.metadata.paymentConditions!.map(async (condition) => {
                    switch (condition.type) {
                        case AccessControlConditionTypes.timelockPayment:
                            return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                    key: '$.tx_responses.*.timestamp',
                                    comparator: '<=',
                                    value: `${condition.intervalInSeconds}`,
                                },
                                condition.feePaymentAmount,
                                condition.feePaymentAddress,
                                condition?.blockHeight,
                                options?.topArgs?.dkgOptions?.chain
                            )
                        default:
                            throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                    }
                }))

                // decrypt
                return await lit.decrypt(scopedRawBlob, publishedList.metadata.encryptedSymmetricKey!, unifiedAccessControlConditions)
            }())
            : (await async function () {
                // transcode to base64url, if needed
                const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                    ? publishedList.StatusList2021.encodedList
                    : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                // if status list 2021 is not fetched, read from file
                if (options?.statusListFile) {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted) {
                        // construct encoded status list
                        const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                        // validate against published list
                        if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: check: revocation: statusListFile does not match published status list 2021')

                        // return encoded
                        return encoded
                    }

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                    // decrypt
                    const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                    // validate against published list
                    if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: check: revocation: statusListFile does not match published status list 2021')

                    // return decrypted
                    return decrypted
                }

                if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: check: revocation: statusListInlineBitstring is required, if statusListFile is not provided')

                // validate against published list
                if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: check: revocation: statusListInlineBitstring does not match published status list 2021')

                // otherwise, read from inline bitstring
                return options?.statusListInlineBitstring
            }())

        // transcode, if needed
        const transcodedStatusList2021 = publishedList.metadata.encoding === 'base64url'
            ? statusList2021
            : toString(fromString(statusList2021, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

        // parse status list 2021
        const statusList = await StatusList.decode({ encodedList: transcodedStatusList2021 })

        // get status by index
        return !!statusList.getStatus(Number(credential.credentialStatus.statusListIndex))
    }

    static async checkSuspended(credential: VerifiableCredential, options: ICheqdStatusList2021Options = { fetchList: true }): Promise<boolean> {
        // validate status purpose
        if (credential.credentialStatus?.statusPurpose !== 'suspension') {
            throw new Error(`[did-provider-cheqd]: check: suspension: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }

        // fetch status list 2021
        const publishedList = (await Cheqd.fetchStatusList2021(credential)) as StatusList2021Suspension

        // fetch status list 2021 inscribed in credential
        const statusList2021 = options?.topArgs?.fetchList
            ? (await async function () {
                // if not encrypted, return bitstring
                if (!publishedList.metadata.encrypted)
                    return publishedList.metadata.encoding === 'base64url'
                        ? publishedList.StatusList2021.encodedList
                        : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                // otherwise, decrypt and return bitstring
                const scopedRawBlob = await toBlob(fromString(publishedList.StatusList2021.encodedList, 'hex'))

                // instantiate dkg-threshold client, in which case lit-protocol is used
                const lit = await LitProtocol.create({
                    chain: options?.topArgs?.dkgOptions?.chain,
                    litNetwork: options?.topArgs?.dkgOptions?.network
                })

                // construct access control conditions
                const unifiedAccessControlConditions = await Promise.all(publishedList.metadata.paymentConditions!.map(async (condition) => {
                    switch (condition.type) {
                        case AccessControlConditionTypes.timelockPayment:
                            return await LitProtocol.generateCosmosAccessControlConditionInverseTimelock({
                                    key: '$.tx_responses.*.timestamp',
                                    comparator: '<=',
                                    value: `${condition.intervalInSeconds}`,
                                },
                                condition.feePaymentAmount,
                                condition.feePaymentAddress,
                                condition?.blockHeight,
                                options?.topArgs?.dkgOptions?.chain
                            )
                        default:
                            throw new Error(`[did-provider-cheqd]: unsupported access control condition type ${condition.type}`)
                    }
                }))

                // decrypt
                return await lit.decrypt(scopedRawBlob, publishedList.metadata.encryptedSymmetricKey!, unifiedAccessControlConditions)
            }())
            : (await async function () {
                // transcode to base64url, if needed
                const publishedListTranscoded = publishedList.metadata.encoding === 'base64url'
                ? publishedList.StatusList2021.encodedList
                : toString(fromString(publishedList.StatusList2021.encodedList, publishedList.metadata.encoding as DefaultStatusList2021Encoding), 'base64url')

                // if status list 2021 is not fetched, read from file
                if (options?.statusListFile) {
                    // if not encrypted, return bitstring
                    if (!publishedList.metadata.encrypted) {
                        // construct encoded status list
                        const encoded = new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode() as Bitstring

                        // validate against published list
                        if (encoded !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: check: suspension: statusListFile does not match published status list 2021')

                        // return encoded
                        return encoded
                    }

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                    // decrypt
                    const decrypted = await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))

                    // validate against published list
                    if (decrypted !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: check: suspension: statusListFile does not match published status list 2021')

                    // return decrypted
                    return decrypted
                }

                if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: check: suspension: statusListInlineBitstring is required, if statusListFile is not provided')

                // validate against published list
                if (options?.statusListInlineBitstring !== publishedListTranscoded) throw new Error('[did-provider-cheqd]: check: suspension: statusListInlineBitstring does not match published status list 2021')

                // otherwise, read from inline bitstring
                return options?.statusListInlineBitstring
            }())

        // parse status list 2021
        const statusList = await StatusList.decode({ encodedList: statusList2021 })

        // get status by index
        return !!statusList.getStatus(Number(credential.credentialStatus.statusListIndex))
    }

    static async publishStatusList2021(statusList2021Raw: Uint8Array, statusList2021Metadata: LinkedResourceMetadataResolutionResult, options: { context: IContext, resourceId?: string, resourceVersion?: string, resourceAlsoKnownAs?: AlternativeUri[], signInputs?: ISignInputs[], fee?: DidStdFee }): Promise<boolean> {
        // construct status list 2021 payload from previous version + new version
        const payload = {
            collectionId: statusList2021Metadata.resourceCollectionId,
            id: options?.resourceId || v4(),
            name: statusList2021Metadata.resourceName,
            version: options?.resourceVersion || new Date().toISOString(),
            alsoKnownAs: options?.resourceAlsoKnownAs || [],
            resourceType: statusList2021Metadata.resourceType as DefaultStatusList2021ResourceType,
            data: statusList2021Raw
        } satisfies StatusList2021ResourcePayload

        return await options.context.agent[BroadcastStatusList2021MethodName]({
            kms: (await options.context.agent.keyManagerGetKeyManagementSystems())[0],
            payload,
            network: statusList2021Metadata.resourceURI.split(':')[2] as CheqdNetwork,
            signInputs: options?.signInputs,
            fee: options?.fee
        })
    }

    static async fetchStatusList2021(credential: VerifiableCredential, returnRaw = false): Promise<StatusList2021Revocation | StatusList2021Suspension | Uint8Array> {
        // validate credential status
        if (!credential.credentialStatus) throw new Error('[did-provider-cheqd]: fetch status list: Credential status is not present')

        // validate credential status type
        if (credential.credentialStatus.type !== 'StatusList2021Entry') throw new Error('[did-provider-cheqd]: fetch status list: Credential status type is not valid')

        // validate credential status list status purpose
        if (credential.credentialStatus.statusPurpose !== 'revocation' && credential.credentialStatus.statusPurpose !== 'suspension') throw new Error('[did-provider-cheqd]: fetch status list: Credential status purpose is not valid')

        // fetch status list 2021
        const content = await (await fetch(credential.credentialStatus.id.split('#')[0])).json() as StatusList2021Revocation | StatusList2021Suspension

        if (!(content.StatusList2021 && content.metadata && content.StatusList2021.encodedList && content.StatusList2021.statusPurpose && content.metadata.encoding)) {
            throw new Error(`'[did-provider-cheqd]: fetch status list: Status List resource content is not valid'`)
        }

        // return raw if requested
        if (returnRaw) {
            return fromString(content.StatusList2021.encodedList, content.metadata.encoding as DefaultStatusList2021Encoding)
        }

        // otherwise, return content
        return content
    }

    static async fetchStatusList2021Metadata(credential: VerifiableCredential): Promise<LinkedResourceMetadataResolutionResult> {
        // get base url
        const baseUrl = new URL(credential.credentialStatus!.id.split('#')[0])

        // get resource name
        const resourceName = baseUrl.searchParams.get('resourceName')

        // get resource type
        const resourceType = baseUrl.searchParams.get('resourceType')

        // unset resource name
        baseUrl.searchParams.delete('resourceName')

        // unset resource type
        baseUrl.searchParams.delete('resourceType')

        // construct metadata url
        const metadataUrl = `${baseUrl.toString()}/metadata`

        // fetch collection metadata
        const collectionMetadata = await (await fetch(metadataUrl)).json() as DIDMetadataDereferencingResult

        // early exit if no linked resources
        if (!collectionMetadata?.contentStream?.linkedResourceMetadata) throw new Error('[did-provider-cheqd]: fetch status list metadata: No linked resources found')

        // find relevant resources by resource name
        const resourceVersioning = collectionMetadata.contentStream.linkedResourceMetadata.filter((resource) => resource.resourceName === resourceName && resource.resourceType === resourceType)

        // early exit if no relevant resources
        if (!resourceVersioning.length || resourceVersioning.length === 0) throw new Error(`[did-provider-cheqd]: fetch status list metadata: No relevant resources found by resource name ${resourceName}`)

        // get latest resource version by nextVersionId null pointer, or by latest created date as fallback
        return resourceVersioning.find((resource) => !resource.nextVersionId) || resourceVersioning.sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime())[0]
    }

    static async loadProvider(document: DIDDocument, providers: CheqdDIDProvider[]): Promise<CheqdDIDProvider> {
        const provider = providers.find((provider) => document.id.includes(`${DidPrefix}:${CheqdDidMethod}:${provider.network}`))
        if (!provider) {
            throw new Error(`[did-provider-cheqd]: Provider namespace not found`)
        }
        return provider
    }

    static generateProviderId(namespace: string): string {
        return `${DidPrefix}:${CheqdDidMethod}:${namespace}`
    }

    static async getFile(filename: string): Promise<Uint8Array> {
        if (typeof filename !== 'string') {
            throw new Error('[did-provider-cheqd]: filename is required')
        }

        if (!fs.existsSync(filename)) {
            debug(`[did-provider-cheqd]: File ${filename} not found`)
            throw new Error(`[did-provider-cheqd]: File ${filename} not found`)
        }

        return new Promise((resolve, reject) => {
            const content = fs.readFileSync(filename)
            if (!content) {
                reject(new Error(`[did-provider-cheqd]: File ${filename} is empty`))
            }
            resolve(new Uint8Array(content))
        })
    }

    static async writeFile(content: Uint8Array, filename?: string): Promise<void> {
        if (!filename) {
            filename = `statusList2021-${v4()}`
        }

        // alert if file exists
        if (fs.existsSync(filename)) {
            debug(`[did-provider-cheqd]: File ${filename} already exists`)
            console.warn(`[did-provider-cheqd]: File ${filename} already exists. Overwriting...`)
        }

        return new Promise((resolve, reject) => {
            fs.writeFile(filename!, content, (err) => {
                if (err) {
                    reject(new Error(`[did-provider-cheqd]: Error writing file ${filename}: reason: ${err}`))
                }
                resolve()
            })
        })
    }

    static async decodeCredentialJWT(jwt: string): Promise<VerifiableCredential> {
        const decodedCredential = decodeJWT(jwt)

        // validate credential payload
        if (!decodedCredential.payload) throw new Error('[did-provider-cheqd]: decode jwt: decodedCredential.payload is required')

        // validate credential payload vc property as VerifiableCredential
        if (!decodedCredential.payload.vc) throw new Error('[did-provider-cheqd]: decode jwt: decodedCredential.payload.vc is required')

        return decodedCredential.payload.vc satisfies VerifiableCredential
    }
}
