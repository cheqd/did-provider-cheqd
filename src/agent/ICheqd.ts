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
    W3CVerifiableCredential
} from '@veramo/core'
import {
    CheqdDIDProvider,
    LinkedResource,
    TImportableEd25519Key,
    ResourcePayload,
    StatusList2021ResourcePayload,
    DefaultRESTUrls
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
    TxNonceFormat
} from '../dkg-threshold/lit-protocol.js';
import { blobToHexString, randomFromRange, toBlob, unescapeUnicode } from '../utils/helpers.js'
import { resolverUrl } from '../did-manager/cheqd-did-resolver.js'

const debug = Debug('veramo:did-provider-cheqd')

export type IContext = IAgentContext<IDIDManager & IKeyManager & IDataStore & IResolver & ICredentialIssuer & ICheqd>
export type TExportedDIDDocWithKeys = { didDoc: DIDDocument, keys: TImportableEd25519Key[], versionId?: string }
export type TExportedDIDDocWithLinkedResourceWithKeys = TExportedDIDDocWithKeys & { linkedResource: LinkedResource }
export type LinkedResourceMetadataResolutionResult = { resourceURI: string, resourceCollectionId: string, resourceId: string, resourceName: string, resourceType: string, mediaType: string, resourceVersion?: string, created: string, checksum: string, previousVersionId: string | null, nextVersionId: string | null }
export type DIDMetadataDereferencingResult = { '@context': 'https://w3id.org/did-resolution/v1', dereferencingMetadata: { contentType: string, retrieved: string, did: { didString: string, methodSpecificId: string, method: string } }, contentStream: { created: string, versionId: string, linkedResourceMetadata: LinkedResourceMetadataResolutionResult[] }, contentMetadata: Record<string, any> }
export type ShallowTypedTx = { body: { messages: any[], memo: string, timeout_height: string, extension_options: any[], non_critical_extension_options: any[] }, auth_info: { signer_infos: { public_key: { '@type': string, key: string }, mode_info: { single: { mode: string } }, sequence: string }[], fee: { amount: Coin[], gas_limit: string, payer: string, granter: string }, tip: any | null }, signatures: string[] }
export type ShallowTypedTxTxResponses = { height: string, txhash: string, codespace: string, code: number, data: string, raw_log: string, logs: any[], info: string, gas_wanted: string, gas_used: string, tx: ShallowTypedTx, timestamp: string, events: any[] }
export type ShallowTypedTxsResponse = { txs: ShallowTypedTx[], tx_responses: ShallowTypedTxTxResponses[], pagination: string | null, total: string } | undefined
export type VerificationResult = { verified: boolean, revoked?: boolean, suspended?: boolean, error?: IVerifyResult['error'] }
export type StatusCheckResult = { revoked?: boolean, suspended?: boolean, error?: IError }
export type RevocationResult = { revoked: boolean, error?: IError, statusList?: Bitstring, encryptedStatusList?: string, encryptedSymmetricKey?: string, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type SuspensionResult = { suspended: boolean, error?: IError, statusList?: Bitstring, encryptedStatusList?: string, encryptedSymmetricKey?: string, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type UnsuspensionResult = { unsuspended: boolean, error?: IError, statusList?: Bitstring, encryptedStatusList?: string, encryptedSymmetricKey?: string, symmetricKey?: string, published?: boolean, resourceMetadata?: LinkedResourceMetadataResolutionResult }
export type Bitstring = string
export type AccessControlConditionType = typeof AccessControlConditionTypes[keyof typeof AccessControlConditionTypes]
export type AccessControlConditionReturnValueComparator = typeof AccessControlConditionReturnValueComparators[keyof typeof AccessControlConditionReturnValueComparators]
export type AccessControlConditionMemoNonceArgs = { senderAddressObserved: string, recipientAddressObserved: string, amountObserved: string, specificNonce?: string, nonceFormat?: TxNonceFormat, type: Extract<AccessControlConditionType, 'memoNonce'> }
export type AccessControlConditionBalanceArgs = { addressObserved: string, amountObserved: string, comparator: AccessControlConditionReturnValueComparator, type: Extract<AccessControlConditionType, 'balance'>}
export type CreateEncryptedStatusList2021Result = { created: boolean, error?: Error, encryptedSymmetricKey: string, symmetricKey?: string, encryptedStatusList2021: string, unifiedAccessControlConditions: CosmosAccessControlCondition[] }
export type GenerateEncryptedStatusList2021Result = { encryptedSymmetricKey: string, encryptedStatusList2021: string, unifiedAccessControlConditions: CosmosAccessControlCondition[] }
export type TransactionResult = { successful: boolean, transactionHash?: string, events?: DeliverTxResponse['events'], rawLog?: string, txResponse?: DeliverTxResponse, error?: IError }
export type ObservationResult = { subscribed: boolean, meetsCondition: boolean, transactionHash?: string, events?: DeliverTxResponse['events'], rawLog?: string, txResponse?: ShallowTypedTxTxResponses, error?: IError }

export const AccessControlConditionTypes = { memoNonce: 'memoNonce', balance: 'balance' } as const
export const AccessControlConditionReturnValueComparators = { lessThan: '<', greaterThan: '>', equalTo: '=', lessThanOrEqualTo: '<=', greaterThanOrEqualTo: '>=' } as const

const CreateIdentifierMethodName = 'cheqdCreateIdentifier'
const UpdateIdentifierMethodName = 'cheqdUpdateIdentifier'
const DeactivateIdentifierMethodName = 'cheqdDeactivateIdentifier'
const CreateResourceMethodName = 'cheqdCreateLinkedResource'
const CreateStatusList2021MethodName = 'cheqdCreateStatusList2021'
const CreateEncryptedStatusList2021MethodName = 'cheqdCreateEncryptedStatusList2021'
const GenerateDidDocMethodName = 'cheqdGenerateDidDoc'
const GenerateDidDocWithLinkedResourceMethodName = 'cheqdGenerateDidDocWithLinkedResource'
const GenerateKeyPairMethodName = 'cheqdGenerateIdentityKeys'
const GenerateVersionIdMethodName = 'cheqdGenerateVersionId'
const GenerateStatusList2021MethodName = 'cheqdGenerateStatusList2021'
const GenerateEncryptedStatusList2021MethodName = 'cheqdGenerateEncryptedStatusList2021'
const IssueRevocableCredentialWithStatusList2021MethodName = 'cheqdIssueRevocableCredentialWithStatusList2021'
const IssueSuspendableCredentialWithStatusList2021MethodName = 'cheqdIssueSuspendableCredentialWithStatusList2021'
const VerifyCredentialMethodName = 'cheqdVerifyCredential'
const VerifyPresentationMethodName = 'cheqdVerifyPresentation' 
const CheckCredentialStatusMethodName = 'cheqdCheckCredentialStatus' 
const RevokeCredentialMethodName = 'cheqdRevokeCredential'
const RevokeCredentialsMethodName = 'cheqdRevokeCredentials'
const SuspendCredentialMethodName = 'cheqdSuspendCredential'
const SuspendCredentialsMethodName = 'cheqdSuspendCredentials'
const UnsuspendCredentialMethodName = 'cheqdUnsuspendCredential'
const UnsuspendCredentialsMethodName = 'cheqdUnsuspendCredentials'
const TransactVerifierPaysIssuerMethodName = 'cheqdTransactVerifierPaysIssuer'
const ObserveVerifierPaysIssuerMethodName = 'cheqdObserveVerifierPaysIssuer'

const DidPrefix = 'did'
const CheqdDidMethod = 'cheqd'

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
    payload: StatusList2021ResourcePayload
    network: CheqdNetwork
    file?: string
    signInputs?: ISignInputs[]
    fee?: DidStdFee
}

export interface ICheqdCreateEncryptedStatusList2021Args extends ICheqdCreateStatusList2021Args {
    encryptionOptions: {
        accessControlConditions: (AccessControlConditionMemoNonceArgs | AccessControlConditionBalanceArgs)[]
        returnSymmetricKey?: boolean
    }
    bootstrapOptions: {
        chain?: LitCompatibleCosmosChain,
        litNetwork?: LitNetwork,
    }
    [key: string]: any
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
    bitstringEncoding?: 'base64' | 'base64url' | 'hex'
    [key: string]: any
}

export interface ICheqdGenerateEncryptedStatusList2021Args extends ICheqdGenerateStatusList2021Args {
    encryptionOptions: {
        accessControlConditions: (AccessControlConditionMemoNonceArgs | AccessControlConditionBalanceArgs)[]
        returnSymmetricKey?: boolean
    }
    bootstrapOptions: {
        chain?: LitCompatibleCosmosChain,
        litNetwork?: LitNetwork,
    }
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
    fetchList?: boolean
    encryptedSymmetricKey?: string
    options?: ICheqdStatusList2021Options
    decryptionOptions: {
        unifiedAccessControlConditions: CosmosAccessControlCondition[]
    }
    bootstrapOptions: {
        chain?: LitCompatibleCosmosChain,
        litNetwork?: LitNetwork,
    }
}

export interface ICheqdVerifyPresentationWithStatusList2021Args {
    presentation: VerifiablePresentation
    fetchList?: boolean
    encryptedSymmetricKey?: string
    options?: ICheqdStatusList2021Options
    decryptionOptions: {
        accessControlConditions: (AccessControlConditionMemoNonceArgs | AccessControlConditionBalanceArgs)[]
    }
    bootstrapOptions: {
        chain?: LitCompatibleCosmosChain,
        litNetwork?: LitNetwork,
    }
}

export interface ICheqdCheckCredentialStatusWithStatusList2021Args {
    credential: W3CVerifiableCredential
    fetchList?: boolean
    encryptedSymmetricKey?: string
    options?: ICheqdStatusList2021Options
    decryptionOptions: {
        accessControlConditions: (AccessControlConditionMemoNonceArgs | AccessControlConditionBalanceArgs)[]
    }
    bootstrapOptions: {
        chain?: LitCompatibleCosmosChain,
        litNetwork?: LitNetwork,
    }
}

export interface ICheqdCredentialStatus {
    id: string
    statusPurpose?: 'revocation' | 'suspension'
    statusListName: string
    statusListIndex: number
    statusListCredential: string
    type: 'StatusList2021Entry'
}

export interface ICheqdRevokeCredentialWithStatusList2021Args {
    credential: W3CVerifiableCredential
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnUpdatedEncryptedStatusList?: boolean
    returnEncryptedSymmetricKey?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    options?: ICheqdStatusList2021Options
}

export interface ICheqdRevokeBulkCredentialsWithStatusList2021Args {
    credentialStatus: ICheqdCredentialStatus & { statusListIndex : number[] }
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnUpdatedEncryptedStatusList?: boolean
    returnEncryptedSymmetricKey?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    options?: ICheqdStatusList2021Options
}

export interface ICheqdSuspendCredentialWithStatusList2021Args {
    credential: W3CVerifiableCredential
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnUpdatedEncryptedStatusList?: boolean
    returnEncryptedSymmetricKey?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    options?: ICheqdStatusList2021Options
}

export interface ICheqdSuspendBulkCredentialsWithStatusList2021Args {
    credentials: W3CVerifiableCredential[]
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnUpdatedEncryptedStatusList?: boolean
    returnEncryptedSymmetricKey?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    options?: ICheqdStatusList2021Options
}

export interface ICheqdUnsuspendCredentialWithStatusList2021Args {
    credential: W3CVerifiableCredential
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnUpdatedEncryptedStatusList?: boolean
    returnEncryptedSymmetricKey?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    options?: ICheqdStatusList2021Options
}

export interface ICheqdUnsuspendBulkCredentialsWithStatusList2021Args {
    credentials: W3CVerifiableCredential[]
    fetchList?: boolean
    publish?: boolean
    publishEncrypted?: boolean
    symmetricKey?: string
    writeToFile?: boolean
    returnUpdatedStatusList?: boolean
    returnUpdatedEncryptedStatusList?: boolean
    returnEncryptedSymmetricKey?: boolean
    returnSymmetricKey?: boolean
    returnStatusListMetadata?: boolean
    options?: ICheqdStatusList2021Options
}

export interface ICheqdTransactVerifierPaysIssuerArgs {
    recipientAddress: string
    amount: Coin
    memoNonce: string
    txBytes?: Uint8Array
    returnTxResponse?: boolean
}

export interface ICheqdObserveVerifierPaysIssuerArgs {
    senderAddress: string
    recipientAddress: string
    amount: Coin
    memoNonce: string
    network?: CheqdNetwork
    unifiedAccessControlCondition?: Required<CosmosAccessControlCondition>
    returnTxResponse?: boolean
}

export interface ICheqdStatusList2021Options {
    statusListFile?: string
    statusListInlineBitstring?: string
    [key: string]: any
}

export interface ICheqd extends IPluginMethodMap {
    [CreateIdentifierMethodName]: (args: ICheqdCreateIdentifierArgs, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>
    [UpdateIdentifierMethodName]: (args: ICheqdUpdateIdentifierArgs, context: IContext) => Promise<Omit<IIdentifier, 'provider'>>,
    [DeactivateIdentifierMethodName]: (args: ICheqdDeactivateIdentifierArgs, context: IContext) => Promise<boolean>,
    [CreateResourceMethodName]: (args: ICheqdCreateLinkedResourceArgs, context: IContext) => Promise<boolean>,
    [CreateStatusList2021MethodName]: (args: ICheqdCreateStatusList2021Args, context: IContext) => Promise<boolean>,
    [CreateEncryptedStatusList2021MethodName]: (args: ICheqdCreateEncryptedStatusList2021Args, context: IContext) => Promise<CreateEncryptedStatusList2021Result>,
    [GenerateDidDocMethodName]: (args: ICheqdGenerateDidDocArgs, context: IContext) => Promise<TExportedDIDDocWithKeys>,
    [GenerateDidDocWithLinkedResourceMethodName]: (args: ICheqdGenerateDidDocWithLinkedResourceArgs, context: IContext) => Promise<TExportedDIDDocWithLinkedResourceWithKeys>,
    [GenerateKeyPairMethodName]: (args: ICheqdGenerateKeyPairArgs, context: IContext) => Promise<TImportableEd25519Key>
    [GenerateVersionIdMethodName]: (args: ICheqdGenerateVersionIdArgs, context: IContext) => Promise<string>
    [GenerateStatusList2021MethodName]: (args: ICheqdGenerateStatusList2021Args, context: IContext) => Promise<string>
    [GenerateEncryptedStatusList2021MethodName]: (args: ICheqdGenerateEncryptedStatusList2021Args, context: IContext) => Promise<GenerateEncryptedStatusList2021Result>
    [IssueRevocableCredentialWithStatusList2021MethodName]: (args: ICheqdIssueRevocableCredentialWithStatusList2021Args, context: IContext) => Promise<VerifiableCredential>
    [IssueSuspendableCredentialWithStatusList2021MethodName]: (args: ICheqdIssueSuspendableCredentialWithStatusList2021Args, context: IContext) => Promise<VerifiableCredential>
    [VerifyCredentialMethodName]: (args: ICheqdVerifyCredentialWithStatusList2021Args, context: IContext) => Promise<VerificationResult>
    [VerifyPresentationMethodName]: (args: ICheqdVerifyPresentationWithStatusList2021Args, context: IContext) => Promise<VerificationResult>
    [CheckCredentialStatusMethodName]: (args: ICheqdCheckCredentialStatusWithStatusList2021Args, context: IContext) => Promise<StatusCheckResult>
    [RevokeCredentialMethodName]: (args: ICheqdRevokeCredentialWithStatusList2021Args, context: IContext) => Promise<RevocationResult>
    [RevokeCredentialsMethodName]: (args: ICheqdRevokeBulkCredentialsWithStatusList2021Args, context: IContext) => Promise<RevocationResult>
    [SuspendCredentialMethodName]: (args: ICheqdSuspendCredentialWithStatusList2021Args, context: IContext) => Promise<SuspensionResult>
    [SuspendCredentialsMethodName]: (args: ICheqdSuspendBulkCredentialsWithStatusList2021Args, context: IContext) => Promise<SuspensionResult[]>
    [UnsuspendCredentialMethodName]: (args: ICheqdUnsuspendCredentialWithStatusList2021Args, context: IContext) => Promise<UnsuspensionResult>
    [UnsuspendCredentialsMethodName]: (args: ICheqdUnsuspendBulkCredentialsWithStatusList2021Args, context: IContext) => Promise<UnsuspensionResult[]>
    [TransactVerifierPaysIssuerMethodName]: (args: ICheqdTransactVerifierPaysIssuerArgs, context: IContext) => Promise<TransactionResult>
    [ObserveVerifierPaysIssuerMethodName]: (args: ICheqdObserveVerifierPaysIssuerArgs, context: IContext) => Promise<ObservationResult>
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
                        "type": "boolean"
                    }
                },
                "cheqdCreateEncryptedStatusList2021": {
                    "description": "Create a new Encrypted Status List 2021",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdCreateEncryptedStatusList2021Args object as any for extensibility"
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
                "cheqdGenerateEncryptedStatusList2021": {
                    "description": "Generate a new encrypted Status List 2021",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdGenerateEncryptedStatusList2021Args object as any for extensibility"
                            }
                        },
                        "required": [
                            "args"
                        ]
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
                "cheqdTransactVerifierPaysIssuer": {
                    "description": "Initiate a transaction where the verifier pays the issuer for a credential status check",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "A cheqdTransactVerifierPaysIssuerArgs object as any for extensibility"
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
                "cheqdObserveVerifierPaysIssuer": {
                    "description": "Observe a transaction where the verifier pays the issuer for a credential status check",
                    "arguments": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "object",
                                "description": "cheqdObserveVerifierPaysIssuerArgs object as any for extensibility"
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
            [CreateEncryptedStatusList2021MethodName]: this.CreateEncryptedStatusList2021.bind(this),
            [GenerateDidDocMethodName]: this.GenerateDidDoc.bind(this),
            [GenerateDidDocWithLinkedResourceMethodName]: this.GenerateDidDocWithLinkedResource.bind(this),
            [GenerateKeyPairMethodName]: this.GenerateIdentityKeys.bind(this),
            [GenerateVersionIdMethodName]: this.GenerateVersionId.bind(this),
            [GenerateStatusList2021MethodName]: this.GenerateStatusList2021.bind(this),
            [GenerateEncryptedStatusList2021MethodName]: this.GenerateEncryptedStatusList2021.bind(this),
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
            [TransactVerifierPaysIssuerMethodName]: this.TransactVerifierPaysIssuer.bind(this),
            [ObserveVerifierPaysIssuerMethodName]: this.ObserveVerifierPaysIssuer.bind(this),
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

        // set default resource type in runtime
        args.payload.resourceType = 'StatusList2021'

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

    private async CreateEncryptedStatusList2021(args: ICheqdCreateEncryptedStatusList2021Args, context: IContext): Promise<CreateEncryptedStatusList2021Result> {
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

        if (!args?.encryptionOptions) {
            throw new Error('[did-provider-cheqd]: encryptionOptions is required')
        }

        if (!args?.bootstrapOptions) {
            throw new Error('[did-provider-cheqd]: bootstrapOptions is required')
        }

        if (!args?.encryptionOptions?.accessControlConditions) {
            throw new Error('[did-provider-cheqd]: accessControlConditions is required')
        }

        // instantiate dkg-threshold client, in which case lit-protocol is used
        const lit = await LitProtocol.create({
            chain: args.bootstrapOptions?.chain,
            litNetwork: args.bootstrapOptions?.litNetwork
        })

        // construct access control conditions
        const unifiedAccessControlConditions = await Promise.all(args.encryptionOptions.accessControlConditions.map(async (condition) => {
            switch (condition.type) {
                case AccessControlConditionTypes.memoNonce:
                    return await LitProtocol.generateCosmosAccessControlConditionTransactionMemo({
                            key: '$.txs.*.body.memo',
                            comparator: 'contains',
                            value: condition?.specificNonce || await LitProtocol.generateTxNonce(condition?.nonceFormat)
                        },
                        condition.amountObserved,
                        condition.senderAddressObserved,
                        condition.recipientAddressObserved,
                        args.bootstrapOptions.chain
                    )
                case AccessControlConditionTypes.balance:
                    return await LitProtocol.generateCosmosAccessControlConditionBalance({
                            key: '$.balances[0].amount',
                            comparator: condition.comparator,
                            value: condition.amountObserved
                        },
                        args.bootstrapOptions.chain,
                        condition.addressObserved
                    )
                default:
                    throw new Error(`[did-provider-cheqd]: accessControlCondition type is not supported`)
            }
        }))

        // encrypt data
        const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(toString(args.payload.data!, 'base64url'), unifiedAccessControlConditions, true)

        // set encrypted data
        args.payload.data = new Uint8Array(await encryptedString.arrayBuffer())

        // set default resource type in runtime
        args.payload.resourceType = 'StatusList2021'

        this.providerId = Cheqd.generateProviderId(args.network)
        this.didProvider = await Cheqd.loadProvider({ id: this.providerId } as DIDDocument, this.supportedDidProviders)

        const created = await this.didProvider.createResource({
            options: {
                kms: args.kms,
                payload: args.payload,
                signInputs: args.signInputs,
                fee: args?.fee
            }
        }, context)

        return {
            created,
            encryptedSymmetricKey,
            encryptedStatusList2021: await blobToHexString(encryptedString),
            symmetricKey: args?.encryptionOptions?.returnSymmetricKey ? toString(symmetricKey!, 'hex') : undefined,
            unifiedAccessControlConditions
        } satisfies CreateEncryptedStatusList2021Result
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

    private async GenerateEncryptedStatusList2021(args: ICheqdGenerateEncryptedStatusList2021Args, context: IContext): Promise<GenerateEncryptedStatusList2021Result> {
        // validate encryptionOptions
        if (!args.encryptionOptions) {
            throw new Error('[did-provider-cheqd]: encryptionOptions is required')
        }

        // validate encryptionOptions.accessControlConditions
        if (!args.encryptionOptions.accessControlConditions) {
            throw new Error('[did-provider-cheqd]: encryptionOptions.accessControlConditions is required')
        }

        // generate status list
        const statusList = args?.buffer
            ? new StatusList({ buffer: args.buffer })
            : new StatusList({ length: args?.length || Cheqd.defaultStatusList2021Length })

        // encode status list
        const encoded = await statusList.encode() as Bitstring

        // instantiate dkg-threshold client, in which case lit-protocol is used
        const lit = await LitProtocol.create({
            chain: args.bootstrapOptions.chain,
            litNetwork: args.bootstrapOptions.litNetwork,
        })

        // construct access control conditions
        const unifiedAccessControlConditions = await Promise.all(args.encryptionOptions.accessControlConditions.map(async (condition) => {
            switch (condition.type) {
                case AccessControlConditionTypes.memoNonce:
                    return await LitProtocol.generateCosmosAccessControlConditionTransactionMemo({
                            key: '$.txs.*.body.memo',
                            comparator: 'contains',
                            value: condition?.specificNonce || await LitProtocol.generateTxNonce(condition?.nonceFormat)
                        },
                        condition.amountObserved,
                        condition.senderAddressObserved,
                        condition.recipientAddressObserved,
                        args.bootstrapOptions.chain
                    )
                case AccessControlConditionTypes.balance:
                    return await LitProtocol.generateCosmosAccessControlConditionBalance({
                            key: '$.balances[0].amount',
                            comparator: condition.comparator,
                            value: condition.amountObserved
                        },
                        args.bootstrapOptions.chain,
                        condition.addressObserved
                    )
                default:
                    throw new Error(`[did-provider-cheqd]: accessControlCondition type is not supported`)
            }
        }))

        // encrypt data
        const { encryptedString, encryptedSymmetricKey } = await lit.encrypt(encoded, unifiedAccessControlConditions)

        // return result
        return {
            encryptedStatusList2021: await blobToHexString(encryptedString),
            encryptedSymmetricKey,
            unifiedAccessControlConditions
        } satisfies GenerateEncryptedStatusList2021Result
    }

    private async IssueRevocableCredentialWithStatusList2021(args: ICheqdIssueRevocableCredentialWithStatusList2021Args, context: IContext): Promise<VerifiableCredential> {
        // generate index
        const statusListIndex = args.statusOptions.statusListIndex || await randomFromRange(args.statusOptions.statusListRangeStart || 0, (args.statusOptions.statusListRangeEnd || Cheqd.defaultStatusList2021Length) - 1, args.statusOptions.indexNotIn || []) 

        // construct issuer
        const issuer = ((args.issuanceOptions.credential.issuer as { id: string }).id)
            ? (args.issuanceOptions.credential.issuer as { id: string }).id
            : args.issuanceOptions.credential.issuer as string

        // generate status list credential
        const statusListCredential = `${resolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}`

        // construct credential status
        const credentialStatus = {
            id: `${statusListCredential}#${statusListIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: 'revocation',
            statusListIndex: `${statusListIndex}`,
            statusListCredential,
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
        const statusListCredential = `${resolverUrl}${issuer}?resourceName=${args.statusOptions.statusListName}`

        // construct credential status
        const credentialStatus = {
            id: `${statusListCredential}#${statusListIndex}`,
            type: 'StatusList2021Entry',
            statusPurpose: 'suspension',
            statusListIndex: `${statusListIndex}`,
            statusListCredential,
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
            credential: args.credential,
            policies: {
                credentialStatus: false
            }
        } satisfies IVerifyCredentialArgs)

        // early return if verification failed
        if (!verificationResult.verified) {
            return { verified: false, error: verificationResult.error }
        }

        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential
        const credentialStatus = await Cheqd.getCredentialStatus(credential)
        // verify credential status
        switch (credential.credentialStatus?.statusPurpose) {
            case 'revocation':
                if (await Cheqd.checkRevoked(credentialStatus, { ...args.options, topArgs: args })) return { verified: false, revoked: true }
                return { verified: true, revoked: false }
            case 'suspension':
                if (await Cheqd.checkSuspended(credentialStatus, { ...args.options, topArgs: args })) return { verified: false, suspended: true }
                return { verified: true, suspended: false }
            default:
                throw new Error(`[did-provider-cheqd]: verify credential: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }
    }

    private async VerifyPresentationWithStatusList2021(args: ICheqdVerifyPresentationWithStatusList2021Args, context: IContext): Promise<VerificationResult> {
        // verify default policies
        const verificationResult = await context.agent.verifyPresentation({
            presentation: args.presentation,
            policies: {
                credentialStatus: false
            }
        } satisfies IVerifyPresentationArgs)

        // early return if verification failed
        if (!verificationResult.verified) {
            return { verified: false, error: verificationResult.error }
        }

        if (!args.presentation.verifiableCredential) throw new Error('[did-provider-cheqd]: verify presentation: presentation.verifiableCredential is required')

        // verify credential(s) status(es)
        for (let credential of args.presentation.verifiableCredential) {
            // if jwt credential, decode it
            if (typeof credential === 'string') credential = await Cheqd.decodeCredentialJWT(credential)
            const credentialStatus = await Cheqd.getCredentialStatus(credential)
            switch (credential.credentialStatus?.statusPurpose) {
                case 'revocation':
                    if (await Cheqd.checkRevoked(credentialStatus, { ...args.options, topArgs: args })) return { verified: false, revoked: true }
                    break
                case 'suspension':
                    if (await Cheqd.checkSuspended(credentialStatus, { ...args.options, topArgs: args })) return { verified: false, suspended: true }
                    break
                default:
                    throw new Error(`[did-provider-cheqd]: verify presentation: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
            }
        }

        return { verified: true }
    }

    private async CheckCredentialStatusWithStatusList2021(args: ICheqdCheckCredentialStatusWithStatusList2021Args, context: IContext): Promise<StatusCheckResult> {
        const credential = typeof args.credential === 'string' ? await Cheqd.decodeCredentialJWT(args.credential) : args.credential
        const credentialStatus = await Cheqd.getCredentialStatus(credential)
        switch (credential.credentialStatus?.statusPurpose) {
            case 'revocation':
                if (await Cheqd.checkRevoked(credentialStatus, { ...args.options, topArgs: args })) return { revoked: true }
                return { revoked: false }
            case 'suspension':
                if (await Cheqd.checkSuspended(credentialStatus, { ...args.options, topArgs: args })) return { suspended: true }
                return { suspended: false }
            default:
                throw new Error(`[did-provider-cheqd]: check status: Unsupported status purpose: ${credential.credentialStatus?.statusPurpose}`)
        }
    }

    private async RevokeCredentialWithStatusList2021(args: ICheqdRevokeCredentialWithStatusList2021Args, context: IContext): Promise<RevocationResult> {
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

        // revoke credential
        return await Cheqd.revokeCredential(await Cheqd.getCredentialStatus(credential), {
            ...args.options,
            topArgs: args,
            publishOptions: {
                context,
                resourceId: args?.options?.resourceId,
                resourceVersion: args?.options?.resourceVersion,
                signInputs: args?.options?.signInputs,
                fee: args?.options?.fee
            }
        })
    }

    private async RevokeBulkCredentialsWithStatusList2021(args: ICheqdRevokeBulkCredentialsWithStatusList2021Args, context: IContext): Promise<RevocationResult> {
        return await Cheqd.revokeCredential(args.credentialStatus, {
            ...args.options,
            topArgs: args,
            publishOptions: {
                context,
                resourceId: args?.options?.resourceId,
                resourceVersion: args?.options?.resourceVersion,
                signInputs: args?.options?.signInputs,
                fee: args?.options?.fee
            }
        })
    }

    private async SuspendCredentialWithStatusList2021(args: ICheqdSuspendCredentialWithStatusList2021Args, context: IContext): Promise<SuspensionResult> {
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
        return await Cheqd.suspendCredential(await Cheqd.getCredentialStatus(credential), {
            ...args.options,
            topArgs: args,
            publishOptions: {
                context,
                resourceId: args?.options?.resourceId,
                resourceVersion: args?.options?.resourceVersion,
                signInputs: args?.options?.signInputs,
                fee: args?.options?.fee
            }
        })
    }

    private async SuspendBulkCredentialsWithStatusList2021(args: ICheqdSuspendBulkCredentialsWithStatusList2021Args, context: IContext): Promise<SuspensionResult[]> {
        // TODO: implement
        throw new Error('[did-provider-cheqd]: suspension: bulk suspension is not implemented yet')
    }

    private async UnsuspendCredentialWithStatusList2021(args: ICheqdUnsuspendCredentialWithStatusList2021Args, context: IContext): Promise<UnsuspensionResult> {
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
        return await Cheqd.unsuspendCredential(await Cheqd.getCredentialStatus(credential), {
            ...args.options,
            topArgs: args,
            publishOptions: {
                context,
                resourceId: args?.options?.resourceId,
                resourceVersion: args?.options?.resourceVersion,
                signInputs: args?.options?.signInputs,
                fee: args?.options?.fee
            }
        })
    }

    private async UnsuspendBulkCredentialsWithStatusList2021(args: ICheqdUnsuspendBulkCredentialsWithStatusList2021Args, context: IContext): Promise<UnsuspensionResult[]> {
        // TODO: implement
        throw new Error('[did-provider-cheqd]: suspension: bulk unsuspension is not implemented yet')
    }

    private async TransactVerifierPaysIssuer(args: ICheqdTransactVerifierPaysIssuerArgs, context: IContext): Promise<TransactionResult> {
        try {
            // delegate to provider
            const transactionResult = await this.didProvider.transactSendTokens({
                recipientAddress: args.recipientAddress,
                amount: args.amount,
                memoNonce: args.memoNonce,
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

    private async ObserveVerifierPaysIssuer(args: ICheqdObserveVerifierPaysIssuerArgs, context: IContext): Promise<ObservationResult> {
        // verify with raw unified access control conditions, if any
        if (args?.unifiedAccessControlCondition) {
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

                // construct url
                const url = `${DefaultRESTUrls[network]}${args.unifiedAccessControlCondition.path}`

                // fetch relevant txs
                const txs = await (await fetch(url)).json() as ShallowTypedTxsResponse

                // skim through txs for relevant events, in which case memoNonce is present and strict equals to the one provided
                const meetsConditionTxIndex = txs?.txs?.findIndex(tx => unescapeUnicode(tx.body.memo) === unescapeUnicode(args.unifiedAccessControlCondition!.returnValueTest.value))

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

        // validate access control conditions components - case: senderAddress
        if (!args.senderAddress) {
            throw new Error('[did-provider-cheqd]: observation: senderAddress is required')
        }

        // validate access control conditions components - case: recipientAddress
        if (!args.recipientAddress) {
            throw new Error('[did-provider-cheqd]: observation: recipientAddress is required')
        }

        // validate access control conditions components - case: amount
        if (!args.amount || !args.amount.amount || !args.amount.denom || args.amount.denom !== 'ncheq') {
            throw new Error('[did-provider-cheqd]: observation: amount is required, and must be an object with amount and denom valid string properties, amongst which denom must be `ncheq`')
        }

        // validate access control conditions components - case: memoNonce
        if (!args.memoNonce) {
            throw new Error('[did-provider-cheqd]: observation: memoNonce is required')
        }

        // validate access control conditions components - case: network
        if (!args.network) {
            throw new Error('[did-provider-cheqd]: observation: network is required')
        }

        try {
            // otherwise, construct url, as per components
            const url = `${DefaultRESTUrls[args.network]}/cosmos/tx/v1beta1/txs?events=transfer.recipient='${args.recipientAddress}'&events=transfer.sender='${args.senderAddress}'&events=transfer.amount='${args.amount.amount}${args.amount.denom}'`

            // fetch relevant txs
            const txs = await (await fetch(url)).json() as ShallowTypedTxsResponse

            // skim through txs for relevant events, in which case memoNonce is present and strict equals to the one provided
            const meetsConditionTxIndex = txs?.txs?.findIndex(tx => unescapeUnicode(tx.body.memo) === unescapeUnicode(args.memoNonce))

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

    static async revokeCredential(credentialStatus: ICheqdCredentialStatus & {statusListIndex: number | number[]}, options?: ICheqdStatusList2021Options): Promise<RevocationResult> {
        try {
            // validate status purpose
            if (credentialStatus.statusPurpose !== 'revocation') throw new Error('[did-provider-cheqd]: revocation: Invalid status purpose')

            // fetch status list 2021 metadata
            const metadata = (await Cheqd.fetchStatusList2021Metadata(credentialStatus))

            // detect if encrypted
            const isEncrypted = function() {
                switch (metadata.mediaType) {
                    case 'application/octet-stream':
                        return true
                    case 'application/gzip':
                        return false
                    default:
                        throw new Error(`[did-provider-cheqd]: revocation: Unsupported media type: ${metadata.mediaType}`)
                }
            }()

            // early return, if encrypted and no decryption key provided
            if (isEncrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: revocation: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!isEncrypted) return await Cheqd.fetchStatusList2021(credentialStatus)

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.fetchStatusList2021(credentialStatus, true) as Uint8Array)

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!isEncrypted) return new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode()

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: revocation: statusListInlineBitstring is required, if statusListFile is not provided')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })
            
            if (Array.isArray(credentialStatus.statusListIndex)) {
                for (var index of credentialStatus.statusListIndex) {
                    let updated = false
                    if (!statusList.getStatus(Number(index))) {
                        // update revocation status
                        statusList.setStatus(Number(index), true)
                        updated = true
                    }

                    if (!updated) return { revoked: false }
                }
            } else {
                // early exit, if credential is already revoked
                if (statusList.getStatus(Number(credentialStatus.statusListIndex))) return { revoked: false }

                // update revocation status
                statusList.setStatus(Number(credentialStatus.statusListIndex), true)
            }

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
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credentialStatus)

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: options?.topArgs?.bootstrapOptions?.chain,
                                litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                            })

                            // encrypt
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, options?.topArgs?.encryptionOptions?.unifiedAccessControlConditions, true)

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(new Uint8Array(await encryptedString.arrayBuffer()), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : [await Cheqd.publishStatusList2021(fromString(bitstring, 'base64url'), statusListMetadata, options?.publishOptions), undefined]

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: revocation: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                revoked: true,
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? bitstring : undefined,
                encryptedStatusList: topArgs?.returnUpdatedEncryptedStatusList ? await blobToHexString((published?.[1] as { encryptedString: Blob })?.encryptedString) : undefined,
                encryptedSymmetricKey: topArgs?.returnEncryptedSymmetricKey ? (published?.[1] as { encryptedSymmetricKey: string })?.encryptedSymmetricKey : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credentialStatus) : undefined
            } satisfies RevocationResult
        } catch (error) {
            // silent fail + early exit, optimised for parallelisation, use with Promise.allSettled
            console.error(error)

            return { revoked: false, error: error as IError } satisfies RevocationResult
        }
    }

    static async suspendCredential(credentialStatus: ICheqdCredentialStatus, options?: ICheqdStatusList2021Options): Promise<SuspensionResult> {
        try {
            // validate status purpose
            if (credentialStatus?.statusPurpose !== 'suspension') throw new Error('[did-provider-cheqd]: suspension: Invalid status purpose')

            // fetch status list 2021 metadata
            const metadata = (await Cheqd.fetchStatusList2021Metadata(credentialStatus))

            // detect if encrypted
            const isEncrypted = function() {
                switch (metadata.mediaType) {
                    case 'application/octet-stream':
                        return true
                    case 'application/gzip':
                        return false
                    default:
                        throw new Error(`[did-provider-cheqd]: suspension: Unsupported media type: ${metadata.mediaType}`)
                }
            }()

            // early return, if encrypted and no decryption key provided
            if (isEncrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: suspension: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!isEncrypted) return await Cheqd.fetchStatusList2021(credentialStatus)

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.fetchStatusList2021(credentialStatus, true) as Uint8Array)

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!isEncrypted) return new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode()

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: suspension: statusListInlineBitstring is required, if statusListFile is not provided')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // early exit, if already suspended
            if (statusList.getStatus(Number(credentialStatus.statusListIndex))) return { suspended: true } satisfies SuspensionResult

            // update suspension status
            statusList.setStatus(Number(credentialStatus.statusListIndex), true)

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
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credentialStatus)

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: options?.topArgs?.bootstrapOptions?.chain,
                                litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                            })

                            // encrypt
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, options?.topArgs?.encryptionOptions?.unifiedAccessControlConditions, true)

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(new Uint8Array(await encryptedString.arrayBuffer()), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : [await Cheqd.publishStatusList2021(fromString(bitstring, 'base64url'), statusListMetadata, options?.publishOptions), undefined]

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: suspension: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                suspended: true,
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? bitstring : undefined,
                encryptedStatusList: topArgs?.returnUpdatedEncryptedStatusList ? await blobToHexString((published?.[1] as { encryptedString: Blob })?.encryptedString) : undefined,
                encryptedSymmetricKey: topArgs?.returnEncryptedSymmetricKey ? (published?.[1] as { encryptedSymmetricKey: string })?.encryptedSymmetricKey : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credentialStatus) : undefined
            } satisfies SuspensionResult
        } catch (error) {
            // silent fail + early exit, optimised for parallelisation, use with Promise.allSettled
            console.error(error)

            return { suspended: false, error: error as IError } satisfies SuspensionResult
        }
    }

    static async unsuspendCredential(credentialStatus: ICheqdCredentialStatus, options?: ICheqdStatusList2021Options): Promise<UnsuspensionResult> {
        try {
            // validate status purpose
            if (credentialStatus?.statusPurpose !== 'suspension') throw new Error('[did-provider-cheqd]: unsuspension: Invalid status purpose')

            // fetch status list 2021 metadata
            const metadata = (await Cheqd.fetchStatusList2021Metadata(credentialStatus))

            // detect if encrypted
            const isEncrypted = function() {
                switch (metadata.mediaType) {
                    case 'application/octet-stream':
                        return true
                    case 'application/gzip':
                        return false
                    default:
                        throw new Error(`[did-provider-cheqd]: unsuspension: Unsupported media type: ${metadata.mediaType}`)
                }
            }()

            // early return, if encrypted and no decryption key provided
            if (isEncrypted && !options?.topArgs?.symmetricKey) throw new Error('[did-provider-cheqd]: unsuspension: symmetricKey is required, if status list 2021 is encrypted')

            // fetch status list 2021 inscribed in credential
            const statusList2021 = options?.topArgs?.fetchList 
                ? (await async function () {
                    // if not encrypted, return bitstring
                    if (!isEncrypted) return await Cheqd.fetchStatusList2021(credentialStatus)

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.fetchStatusList2021(credentialStatus, true) as Uint8Array)

                    // decrypt
                    return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                }())
                : (await async function () {
                    // if status list 2021 is not fetched, read from file
                    if (options?.statusListFile) {
                        // if not encrypted, return bitstring
                        if (!isEncrypted) return new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode()

                        // otherwise, decrypt and return bitstring
                        const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                        // decrypt
                        return await LitProtocol.decryptDirect(scopedRawBlob, fromString(options?.topArgs?.symmetricKey, 'hex'))
                    }

                    if (!options?.statusListInlineBitstring) throw new Error('[did-provider-cheqd]: unsuspension: statusListInlineBitstring is required, if statusListFile is not provided')

                    // otherwise, read from inline bitstring
                    return options?.statusListInlineBitstring
                }())

            // parse status list 2021
            const statusList = await StatusList.decode({ encodedList: statusList2021 })

            // early exit, if already unsuspended
            if (!statusList.getStatus(Number(credentialStatus.statusListIndex))) return { unsuspended: true } satisfies UnsuspensionResult

            // update suspension status
            statusList.setStatus(Number(credentialStatus.statusListIndex), false)

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
                    const statusListMetadata = await Cheqd.fetchStatusList2021Metadata(credentialStatus)

                    // publish status list 2021 as new version
                    const scoped = topArgs.publishEncrypted
                        ? (await async function () {
                            // instantiate dkg-threshold client, in which case lit-protocol is used
                            const lit = await LitProtocol.create({
                                chain: options?.topArgs?.bootstrapOptions?.chain,
                                litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                            })

                            // encrypt
                            const { encryptedString, encryptedSymmetricKey, symmetricKey } = await lit.encrypt(bitstring, options?.topArgs?.encryptionOptions?.unifiedAccessControlConditions, true)

                            // return tuple of publish result and encryption relevant metadata
                            return [
                                await Cheqd.publishStatusList2021(new Uint8Array(await encryptedString.arrayBuffer()), statusListMetadata, options?.publishOptions),
                                { encryptedString, encryptedSymmetricKey, symmetricKey: toString(symmetricKey!, 'hex') }
                            ]
                        }())
                        : [await Cheqd.publishStatusList2021(fromString(bitstring, 'base64url'), statusListMetadata, options?.publishOptions), undefined]

                    // early exit, if publish failed
                    if (!scoped[0]) throw new Error('[did-provider-cheqd]: unsuspension: Failed to publish status list 2021')

                    // return publish result
                    return scoped
                }())
                : undefined

            return {
                unsuspended: true,
                published: topArgs?.publish ? true : undefined,
                statusList: topArgs?.returnUpdatedStatusList ? bitstring : undefined,
                encryptedStatusList: topArgs?.returnUpdatedEncryptedStatusList ? await blobToHexString((published?.[1] as { encryptedString: Blob })?.encryptedString) : undefined,
                encryptedSymmetricKey: topArgs?.returnEncryptedSymmetricKey ? (published?.[1] as { encryptedSymmetricKey: string })?.encryptedSymmetricKey : undefined,
                symmetricKey: topArgs?.returnSymmetricKey ? (published?.[1] as { symmetricKey: string })?.symmetricKey : undefined,
                resourceMetadata: topArgs?.returnStatusListMetadata ? await Cheqd.fetchStatusList2021Metadata(credentialStatus) : undefined
            } satisfies UnsuspensionResult
        } catch (error) {
            // silent fail + early exit, optimised for parallelisation, use with Promise.allSettled
            console.error(error)

            return { unsuspended: false, error: error as IError } satisfies UnsuspensionResult
        }
    }

    static async checkRevoked(credentialStatus: ICheqdCredentialStatus, options: ICheqdStatusList2021Options = { fetchList: true }): Promise<boolean> {
        // validate status purpose
        if (credentialStatus.statusPurpose !== 'revocation') {
            throw new Error(`[did-provider-cheqd]: revocation: Unsupported status purpose: ${credentialStatus.statusPurpose}`)
        }

        // fetch status list 2021 metadata
        const metadata = (await Cheqd.fetchStatusList2021Metadata(credentialStatus))

        // detect if encrypted
        const isEncrypted = function() {
            switch (metadata.mediaType) {
                case 'application/octet-stream':
                    return true
                case 'application/gzip':
                    return false
                default:
                    throw new Error(`[did-provider-cheqd]: revocation: Unsupported media type: ${metadata.mediaType}`)
            }
        }()

        // early return, if encrypted and decryption key is not provided
        if (isEncrypted && !options?.topArgs?.encryptedSymmetricKey) throw new Error('[did-provider-cheqd]: revocation: encryptedSymmetricKey is required, if status list 2021 is encrypted')

        // fetch status list 2021 inscribed in credential
        const statusList2021 = options?.topArgs?.fetchList
            ? (await async function () {
                // if not encrypted, return bitstring
                if (!isEncrypted) return await Cheqd.fetchStatusList2021(credentialStatus)

                // otherwise, decrypt and return bitstring
                const scopedRawBlob = await toBlob(await Cheqd.fetchStatusList2021(credentialStatus, true) as Uint8Array)

                // instantiate dkg-threshold client, in which case lit-protocol is used
                const lit = await LitProtocol.create({
                    chain: options?.topArgs?.bootstrapOptions?.chain,
                    litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                })

                // decrypt
                return await lit.decrypt(scopedRawBlob, options?.topArgs?.encryptedSymmetricKey, options?.topArgs?.decryptionOptions?.unifiedAccessControlConditions)
            }())
            : (await async function () {
                // if status list 2021 is not fetched, read from file
                if (options?.statusListFile) {
                    // if not encrypted, return bitstring
                    if (!isEncrypted) return new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode()

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                    // instantiate dkg-threshold client, in which case lit-protocol is used
                    const lit = await LitProtocol.create({
                        chain: options?.topArgs?.bootstrapOptions?.chain,
                        litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                    })

                    // decrypt
                    return await lit.decrypt(scopedRawBlob, options?.topArgs?.encryptedSymmetricKey, options?.topArgs?.decryptionOptions?.unifiedAccessControlConditions)
                }

                if (!options?.statusListInlineBitstring) throw new Error(' [did-provider-cheqd]: revocation: statusListInlineBitstring is required, if statusListFile is not provided')

                // otherwise, read from inline bitstring
                return options?.statusListInlineBitstring
            }())

        // parse status list 2021
        const statusList = await StatusList.decode({ encodedList: statusList2021 })

        // get status by index
        return !!statusList.getStatus(Number(credentialStatus.statusListIndex))
    }

    static async checkSuspended(credentialStatus: ICheqdCredentialStatus, options: ICheqdStatusList2021Options = { fetchList: true }): Promise<boolean> {
        // validate status purpose
        if (credentialStatus.statusPurpose !== 'suspension') {
            throw new Error(`[did-provider-cheqd]: suspension: Unsupported status purpose: ${credentialStatus.statusPurpose}`)
        }

        // fetch status list 2021 metadata
        const metadata = (await Cheqd.fetchStatusList2021Metadata(credentialStatus))

        // detect if encrypted
        const isEncrypted = function() {
            switch (metadata.mediaType) {
                case 'application/octet-stream':
                    return true
                case 'application/gzip':
                    return false
                default:
                    throw new Error(`[did-provider-cheqd]: suspension: Unsupported media type: ${metadata.mediaType}`)
            }
        }()

        // early return, if encrypted and decryption key is not provided
        if (isEncrypted && !options?.topArgs?.encryptedSymmetricKey) throw new Error('[did-provider-cheqd]: suspension: encryptedSymmetricKey is required, if status list 2021 is encrypted')

        // fetch status list 2021 inscribed in credential
        const statusList2021 = options?.topArgs?.fetchList
            ? (await async function () {
                // if not encrypted, return bitstring
                if (!isEncrypted) return await Cheqd.fetchStatusList2021(credentialStatus)

                // otherwise, decrypt and return bitstring
                const scopedRawBlob = await toBlob(await Cheqd.fetchStatusList2021(credentialStatus, true) as Uint8Array)

                // instantiate dkg-threshold client, in which case lit-protocol is used
                const lit = await LitProtocol.create({
                    chain: options?.topArgs?.bootstrapOptions?.chain,
                    litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                })

                // decrypt
                return await lit.decrypt(scopedRawBlob, options?.topArgs?.encryptedSymmetricKey, options?.topArgs?.decryptionOptions?.unifiedAccessControlConditions)
            }())
            : (await async function () {
                // if status list 2021 is not fetched, read from file
                if (options?.statusListFile) {
                    // if not encrypted, return bitstring
                    if (!isEncrypted) return new StatusList({ buffer: await Cheqd.getFile(options.statusListFile) }).encode()

                    // otherwise, decrypt and return bitstring
                    const scopedRawBlob = await toBlob(await Cheqd.getFile(options.statusListFile))

                    // instantiate dkg-threshold client, in which case lit-protocol is used
                    const lit = await LitProtocol.create({
                        chain: options?.topArgs?.bootstrapOptions?.chain,
                        litNetwork: options?.topArgs?.bootstrapOptions?.litNetwork
                    })

                    // decrypt
                    return await lit.decrypt(scopedRawBlob, options?.topArgs?.encryptedSymmetricKey, options?.topArgs?.decryptionOptions?.unifiedAccessControlConditions)
                }

                if (!options?.statusListInlineBitstring) throw new Error(' [did-provider-cheqd]: suspension: statusListInlineBitstring is required, if statusListFile is not provided')

                // otherwise, read from inline bitstring
                return options?.statusListInlineBitstring
            }())

        // parse status list 2021
        const statusList = await StatusList.decode({ encodedList: statusList2021 })

        // get status by index
        return !!statusList.getStatus(Number(credentialStatus.statusListIndex))
    }

    static async publishStatusList2021(statusList2021Raw: Uint8Array, statusList2021Metadata: LinkedResourceMetadataResolutionResult, options: { context: IContext, resourceId?: string, resourceVersion?: string, signInputs?: ISignInputs[], fee?: DidStdFee }): Promise<boolean> {
        // construct status list 2021 payload from previous version + new version
        const payload = {
            collectionId: statusList2021Metadata.resourceCollectionId,
            id: options?.resourceId || v4(),
            name: statusList2021Metadata.resourceName,
            version: options?.resourceVersion || new Date().toISOString(),
            resourceType: 'StatusList2021',
            data: statusList2021Raw
        } satisfies StatusList2021ResourcePayload

        return await options.context.agent[CreateStatusList2021MethodName]({
            kms: (await options.context.agent.keyManagerGetKeyManagementSystems())[0],
            payload,
            network: statusList2021Metadata.resourceURI.split(':')[2] as CheqdNetwork,
            signInputs: options?.signInputs,
            fee: options?.fee
        })
    }

    static async fetchStatusList2021(credentialStatus: ICheqdCredentialStatus, returnRaw = false): Promise<Bitstring | Uint8Array> {
        // validate credential status
        if (!credentialStatus) throw new Error('[did-provider-cheqd]: fetch status list: Credential status is not present')

        // validate credential status type
        if (credentialStatus.type !== 'StatusList2021Entry') throw new Error('[did-provider-cheqd]: fetch status list: Credential status type is not valid')

        // validate credential status list status purpose
        if (credentialStatus.statusPurpose !== 'revocation' && credentialStatus.statusPurpose !== 'suspension') throw new Error('[did-provider-cheqd]: fetch status list: Credential status purpose is not valid')

        // validate credential status list status list credential
        if (!credentialStatus.statusListCredential) throw new Error('[did-provider-cheqd]: fetch status list: Credential status list credential is not present')

        // fetch status list 2021
        const raw = await (await fetch(credentialStatus.statusListCredential)).arrayBuffer()

        // return raw if requested
        if (returnRaw) return new Uint8Array(raw)

        // otherwise, parse to bitstring and return
        const bitstring = toString(new Uint8Array(raw), 'base64url')

        return bitstring
    }

    static async fetchStatusList2021Metadata(credentialStatus: ICheqdCredentialStatus): Promise<LinkedResourceMetadataResolutionResult> {
        // get base url
        const baseUrl = new URL(credentialStatus.statusListCredential)
        
        // get resource name
        const resourceName = baseUrl.searchParams.get('resourceName')

        // unset resource name
        baseUrl.searchParams.delete('resourceName')

        // construct metadata url
        const metadataUrl = `${baseUrl.toString()}/metadata`

        // fetch collection metadata
        const collectionMetadata = await (await fetch(metadataUrl)).json() as DIDMetadataDereferencingResult

        // early exit if no linked resources
        if (!collectionMetadata?.contentStream?.linkedResourceMetadata) throw new Error('[did-provider-cheqd]: fetch status list metadata: No linked resources found')

        // find relevant resources by resource name
        const resourceVersioning = collectionMetadata.contentStream.linkedResourceMetadata.filter((resource) => resource.resourceName === resourceName)

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

    static async getCredentialStatus(credential: VerifiableCredential): Promise<ICheqdCredentialStatus> {
        // validate credential status property
        if (!credential.credentialStatus) throw new Error('[did-provider-cheqd]: credential status: credentialStatus is required')

        // validate statusPurpose
        if(!credential.credentialStatus.statusPurpose) throw new Error('[did-provider-cheqd]: credential status: credentialStatus purpose is required')

        // validate statusName
        if(!credential.credentialStatus.statusListName) throw new Error('[did-provider-cheqd]: credential status: credentialStatus name is required')

        // validate statusIndex
        if(!credential.credentialStatus.statusListIndex) throw new Error('[did-provider-cheqd]: credential status: credentialStatus index is required')

        // validate statusType
        if(!credential.credentialStatus.type) throw new Error('[did-provider-cheqd]: credential status: credentialStatus type is required')

        // validate statusCredenital
        if(!credential.credentialStatus.statusListCredential) throw new Error('[did-provider-cheqd]: credential status: credentialStatus statusListCredential is required')

        return credential.credentialStatus as unknown as ICheqdCredentialStatus
    }
}
