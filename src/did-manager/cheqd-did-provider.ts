/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, @typescript-eslint/no-non-null-assertion */
// any is used for extensibility
// unused vars are kept by convention
// non-null assertion is used when we know better than the compiler that the value is not null or undefined
import {
	CheqdSDK,
	createCheqdSDK,
	createSignInputsFromImportableEd25519Key,
	DIDModule,
	ICheqdSDKOptions,
	AbstractCheqdSDKModule,
	ResourceModule,
	VerificationMethod,
	DidStdFee,
	ISignInputs,
	IContext as ISDKContext,
	CheqdNetwork,
	VerificationMethods,
	toMultibaseRaw,
} from '@cheqd/sdk';
import { MsgCreateResourcePayload } from '@cheqd/ts-proto/cheqd/resource/v2/index.js';
import { AccountData, Coin, DirectSecp256k1HdWallet, DirectSecp256k1Wallet } from '@cosmjs/proto-signing';
import { GasPrice, DeliverTxResponse } from '@cosmjs/stargate';
import { assert } from '@cosmjs/utils';
import { DIDDocument, DIDResolutionResult } from 'did-resolver';
import {
	IIdentifier,
	IKey,
	IService,
	IAgentContext,
	IKeyManager,
	ManagedKeyInfo,
	MinimalImportableKey,
	TKeyType,
	IKeyManagerGetArgs,
} from '@veramo/core';
import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { base64ToBytes, extractPublicKeyHex } from '@veramo/utils';
import Debug from 'debug';
import { EnglishMnemonic as _, Ed25519 } from '@cosmjs/crypto';
import { fromString, toString } from 'uint8arrays';
import { MsgCreateDidDocPayload, MsgDeactivateDidDocPayload, SignInfo } from '@cheqd/ts-proto/cheqd/did/v2/index.js';
import { v4 } from 'uuid';
import {
	LitCompatibleCosmosChain,
	LitCompatibleCosmosChains,
	LitNetwork,
	LitNetworks,
} from '../dkg-threshold/lit-protocol.js';
import { IContext } from '../agent/ICheqd.js';

import { bases } from 'multiformats/basics';
import { getControllers } from '../utils/helpers.js';

const debug = Debug('veramo:did-provider-cheqd');

export const DefaultRPCUrls = {
	[CheqdNetwork.Mainnet]: 'https://rpc.cheqd.net',
	[CheqdNetwork.Testnet]: 'https://rpc.cheqd.network',
} as const;

export const DefaultRESTUrls = {
	[CheqdNetwork.Mainnet]: 'https://api.cheqd.net',
	[CheqdNetwork.Testnet]: 'https://api.cheqd.network',
} as const;

export const DefaultDkgSupportedChains = {
	[CheqdNetwork.Mainnet]: LitCompatibleCosmosChains.cheqdMainnet,
	[CheqdNetwork.Testnet]: LitCompatibleCosmosChains.cheqdTestnet,
} as const;

export const DefaultStatusList2021StatusPurposeTypes = {
	revocation: 'revocation',
	suspension: 'suspension',
} as const;

export const DefaultStatusList2021ResourceTypes = {
	default: 'StatusList2021',
	revocation: 'StatusList2021Revocation',
	suspension: 'StatusList2021Suspension',
} as const;

export const DefaultStatusList2021Encodings = {
	base64: 'base64',
	base64url: 'base64url',
	hex: 'hex',
} as const;

export type DefaultRPCUrl = (typeof DefaultRPCUrls)[keyof typeof DefaultRPCUrls];

export type DefaultRESTUrl = (typeof DefaultRESTUrls)[keyof typeof DefaultRESTUrls];

export type DefaultStatusList2021ResourceType =
	(typeof DefaultStatusList2021ResourceTypes)[keyof typeof DefaultStatusList2021ResourceTypes];

export type DefaultStatusList2021StatusPurposeType =
	(typeof DefaultStatusList2021StatusPurposeTypes)[keyof typeof DefaultStatusList2021StatusPurposeTypes];

export type DefaultStatusList2021Encoding =
	(typeof DefaultStatusList2021Encodings)[keyof typeof DefaultStatusList2021Encodings];

export type LinkedResource = Omit<MsgCreateResourcePayload, 'data'> & { data?: string };

export type ResourcePayload = Partial<MsgCreateResourcePayload>;

export type StatusList2021ResourcePayload = ResourcePayload & { resourceType: DefaultStatusList2021ResourceType };

export type TImportableEd25519Key = Required<Pick<IKey, 'publicKeyHex' | 'privateKeyHex'>> & {
	kid: TImportableEd25519Key['publicKeyHex'];
	type: 'Ed25519';
};

declare const TImportableEd25519Key: {
	isTImportableEd25519Key(object: object[]): object is TImportableEd25519Key[];
};

export type TSupportedKeyType = 'Ed25519' | 'Secp256k1';

export class EnglishMnemonic extends _ {
	static readonly _mnemonicMatcher = /^[a-z]+( [a-z]+)*$/;
}

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:cheqd` identifiers.
 * @public
 */
export class CheqdDIDProvider extends AbstractIdentifierProvider {
	private defaultKms: string;
	public readonly network: CheqdNetwork;
	public readonly rpcUrl: string;
	private readonly cosmosPayerWallet: Promise<DirectSecp256k1HdWallet | DirectSecp256k1Wallet>;
	public readonly dkgOptions: {
		chain: Extract<LitCompatibleCosmosChain, 'cheqdTestnet' | 'cheqdMainnet'>;
		network: LitNetwork;
	};
	private sdk?: CheqdSDK;
	private fee?: DidStdFee;

	static readonly defaultGasPrice = GasPrice.fromString('50ncheq');

	constructor(options: {
		defaultKms: string;
		cosmosPayerSeed: string;
		networkType?: CheqdNetwork;
		rpcUrl?: string;
		dkgOptions?: {
			chain?: Extract<LitCompatibleCosmosChain, 'cheqdTestnet' | 'cheqdMainnet'>;
			network?: LitNetwork;
		};
	}) {
		super();
		this.defaultKms = options.defaultKms;
		this.network = options.networkType ? options.networkType : CheqdNetwork.Testnet;
		this.rpcUrl = options.rpcUrl ? options.rpcUrl : DefaultRPCUrls[this.network];
		this.dkgOptions = options.dkgOptions
			? {
					chain: options.dkgOptions.chain
						? options.dkgOptions.chain
						: DefaultDkgSupportedChains[this.network],
					network: options.dkgOptions.network ? options.dkgOptions.network : LitNetworks.serrano,
				}
			: { chain: DefaultDkgSupportedChains[this.network], network: LitNetworks.serrano };

		if (!options?.cosmosPayerSeed || options.cosmosPayerSeed === '') {
			this.cosmosPayerWallet = DirectSecp256k1HdWallet.generate();
			return;
		}
		this.cosmosPayerWallet = EnglishMnemonic._mnemonicMatcher.test(options.cosmosPayerSeed)
			? DirectSecp256k1HdWallet.fromMnemonic(options.cosmosPayerSeed, { prefix: 'cheqd' })
			: DirectSecp256k1Wallet.fromKey(fromString(options.cosmosPayerSeed.replace(/^0x/, ''), 'hex'), 'cheqd');
	}

	async getWalletAccounts(): Promise<readonly AccountData[]> {
		return await (await this.cosmosPayerWallet).getAccounts();
	}

	private async getCheqdSDK(fee?: DidStdFee, gasPrice?: GasPrice): Promise<CheqdSDK> {
		if (!this.sdk) {
			const wallet = await this.cosmosPayerWallet.catch(() => {
				throw new Error(`[did-provider-cheqd]: network: ${this.network} valid cosmosPayerSeed is required`);
			});
			const sdkOptions: ICheqdSDKOptions = {
				modules: [
					DIDModule as unknown as AbstractCheqdSDKModule,
					ResourceModule as unknown as AbstractCheqdSDKModule,
				],
				rpcUrl: this.rpcUrl,
				wallet: wallet,
				gasPrice,
			};

			this.sdk = await createCheqdSDK(sdkOptions);
			this.fee = fee;

			if (this?.fee && !this?.fee?.payer) {
				const feePayer = (await (await this.cosmosPayerWallet).getAccounts())[0].address;
				this.fee.payer = feePayer;
			}
		}
		return this.sdk!;
	}

	async createIdentifier(
		{
			kms,
			options,
		}: {
			kms?: string;
			alias?: string;
			options: { document: DIDDocument; keys?: TImportableEd25519Key[]; versionId?: string; fee?: DidStdFee };
		},
		context: IContext
	): Promise<Omit<IIdentifier, 'provider'>> {
		const sdk = await this.getCheqdSDK(options?.fee);
		const versionId = options.versionId || v4();
		const signInputs: ISignInputs[] | SignInfo[] = options.keys
			? (function () {
					return options.keys.map((key) =>
						createSignInputsFromImportableEd25519Key(key, options.document.verificationMethod || [])
					);
				})()
			: await (async function (that: CheqdDIDProvider) {
					const data = await createMsgCreateDidDocPayloadToSign(options.document, versionId);
					return await that.signPayload(context, data, options.document.verificationMethod);
				})(this);

		const tx = await sdk.createDidDocTx(signInputs, options.document, '', this?.fee, undefined, versionId, {
			sdk: sdk,
		} satisfies ISDKContext);

		assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`);

		//* Currently, only one controller key is supported.
		//* We assume that the first key in the list is the controller key.
		//* This is subject to change in the near future.
		const keys: ManagedKeyInfo[] = options.keys
			? await (async function (that: CheqdDIDProvider) {
					const scopedKeys: ManagedKeyInfo[] = [];
					for (const key of options.keys!) {
						let managedKey: ManagedKeyInfo | undefined;
						try {
							managedKey = await context.agent.keyManagerImport({
								...key,
								kms: kms || that.defaultKms,
							} satisfies MinimalImportableKey);
						} catch (e) {
							debug(`Failed to import key ${key.kid}. Reason: ${e}`);

							// construct key, if it failed to import
							managedKey = { ...key, kms: kms || that.defaultKms };
						}
						if (managedKey) {
							scopedKeys.push(managedKey);
						}
					}
					return scopedKeys;
				})(this)
			: await this.getKeysFromVerificationMethod(context, options.document.verificationMethod);

		const controllerKey: IKey = keys[0];
		const identifier: IIdentifier = {
			did: <string>options.document.id,
			controllerKeyId: controllerKey.kid,
			keys,
			services: options.document.service || [],
			provider: options.document.id.split(':').splice(0, 3).join(':'),
		};

		debug('Created DID', identifier.did);

		return identifier;
	}

	async compileSignInfos(
		payload: Uint8Array,
		controllers: string[],
		options: {
			context: IContext;
			publicKeyHexs?: string[];
			versionId?: string
		}): Promise<SignInfo[]> {
		// 1. Iterate over the contollers and for each - get DIDDocument and get the verificationMethodId associated with one of publicKeyHexs
		// 1.1 Iterate over the list of verificationMethods and make the checks:
		// 1.1.1 Iterate over publicKeyHexs and convert each publicKeyHex to the verification Material
		// 1.1.2 If it compares with the one in the verificationMethod, then we have a match and can store the pair of verificationMethodId and publicKeyHex
		// 2. Iterate over the pair of verificationMethodIds and publicKeys and create SignInfo

		// Setup 
		const publicKeyHexs = options.publicKeyHexs || [];
		if (publicKeyHexs.length === 0) {
			for (const controller of controllers) {
				const key = await options.context.agent.didManagerGet({ did: controller }).then((result) => result.keys[0]);
				publicKeyHexs.push(key.kid)
			}
		}
		const signInfos: SignInfo[] = [];

		// Get verificationMethodIds
		const verificationMethodIds: {
			verificationMethodId: string,
			publicKeyHex: string,
		}[] = [];

		// Iterate over list of controllers and tries to get the corresponding verificationMethodId associated with one of publicKeyHexs
		for (const controller of controllers) {
			// We need to get here current version of DIDDocument associated with the controller and cannot skip it even if document.id === controller
			// cause in case of remooving verifcation method we need to sign the payload with the old verification method which is on ledger.
			const controllerDidDocument = await options.context.agent.resolveDid({ didUrl: controller }).then((result) => result.didDocument);
			// Check if controller DID document is resolved
			if (!controllerDidDocument) {
				throw new Error('[did-provider-cheqd]: updateIdentifierSignInfos: Erro while resolving the DID document for controller DID: ' + controller);
			}
			// Check if controller DID document contains verification methods
			if (!controllerDidDocument.verificationMethod) {
				throw new Error('[did-provider-cheqd]: updateIdentifierSignInfos: Controller DID document does not contain verification methods');
			}
			// Iterate over verificationMethods and by comparing publicKeys get the verificationMethod Id
			for (const vm of controllerDidDocument.verificationMethod) {
				// Try to match verificationMethod with one of publicKeyHexs
				const verificationMethodId = ( function (){
					for (const publicKeyHex of publicKeyHexs) {
						// Transform to string
						const publicKey = fromString(publicKeyHex, 'hex');
						switch (vm?.type) {
							case VerificationMethods.Ed255192020: {
								const publicKeyMultibase = toMultibaseRaw(publicKey);
								if (vm.publicKeyMultibase === publicKeyMultibase) {
									return {
										verificationMethodId: vm.id,
										publicKeyHex: publicKeyHex
									}
								}
								break;
							}
							case VerificationMethods.Ed255192018: {
								const publicKeyBase58 = bases['base58btc'].encode(publicKey).slice(1);
								if (vm.publicKeyBase58 === publicKeyBase58) {
									return {
										verificationMethodId: vm.id,
										publicKeyHex: publicKeyHex
									}
								}
								break;
							}
							case VerificationMethods.JWK: {
								const publicKeyJwk: JsonWebKey = {
									crv: 'Ed25519',
									kty: 'OKP',
									x: toString(publicKey, 'base64url'),
								};
								if (JSON.stringify(vm.publicKeyJwk) === JSON.stringify(publicKeyJwk)) {
									return {
										verificationMethodId: vm.id,
										publicKeyHex: publicKeyHex
									}
								}
								break;
							}
						}
					}
				})()

				// To optimization, if verificationMethodId is found, push it to verificationMethodIds and remove publicKeyHex from publicKeyHexs
				if (verificationMethodId) {
					verificationMethodIds.push(verificationMethodId);
					publicKeyHexs.splice(publicKeyHexs.indexOf(verificationMethodId.publicKeyHex), 1);
				}
			}
		}

		// Iterate over pair of verificationMethodIds and publicKeys and create SignInfo
		for (const { verificationMethodId, publicKeyHex } of verificationMethodIds) {
			
			signInfos.push({
				verificationMethodId,
				signature: base64ToBytes(
					await options.context.agent.keyManagerSign({
						keyRef: publicKeyHex,
						data: toString(payload, 'hex'),
						encoding: 'hex',
					})
				),
			} satisfies SignInfo)
		}
		return signInfos

		}

	async updateIdentifierCompileSignInfos(
		didDocument: DIDDocument, 
		options: {
			context: IContext;
			publicKeyHexs?: string[];
			versionId?: string
		}): Promise<SignInfo[]> {

		// Steps to solve the issue:
		// 1. Collect list of controllers. The user can remove, append and reqrite the controller.
		//   But we need to send all the signatures, old and news
		// 2. Generate payloads
		// 3. Compile list of signInfos

		// Get current version of DIDDocument
		const actualDIDDocument: DIDResolutionResult = await options.context.agent.resolveDid({ didUrl: didDocument.id });
		if (!actualDIDDocument.didDocument) {
			throw new Error('[did-provider-cheqd]: updateIdentifierSignInfos: Erro while resolving the DID document for updating with error: ' + actualDIDDocument.didResolutionMetadata.error);
		}
		// Compile controllers
		const updatedControllers: string[] = getControllers(didDocument);
		const actualControllers: string[] = getControllers(actualDIDDocument.didDocument);
		const controllers = [...new Set([...updatedControllers, ...actualControllers])];

		// Generate payload
		const versionId = options.versionId || v4();
		const payload = await createMsgCreateDidDocPayloadToSign(didDocument, versionId);

		return await this.compileSignInfos(payload, controllers, options);
		
	}

	async deactivateIdentifierCompileSignInfos(
		didDocument: DIDDocument, 
		options: {
			context: IContext;
			publicKeyHexs?: string[];
			versionId?: string
		}): Promise<SignInfo[]> {

		// Steps to solve the issue:
		// 1. Collect list of controllers. The user can remove, append and reqrite the controller.
		//   But we need to send all the signatures, old and news
		// Generate payload to sign
		// 3. Compile list of signInfos

		// Get Controllers
		const controllers: string[] = getControllers(didDocument);

		// Generate payload
		const versionId = options.versionId || v4();
		const payload = await createMsgDeactivateDidDocPayloadToSign(didDocument, versionId);

		// Compile signInfos
		return await this.compileSignInfos(payload, controllers, options);
	}


	async updateIdentifier(
		{
			did,
			document,
			options,
		}: {
			did: string;
			document: DIDDocument;
			options: {
				 kms: string; 
				 keys?: TImportableEd25519Key[]; 
				 versionId?: string; 
				 fee?: DidStdFee;
				 publicKeyHexs?: string[];
				};
		},
		context: IContext
	): Promise<IIdentifier> {
		const sdk = await this.getCheqdSDK(options?.fee);
		const versionId = options.versionId || v4();
		const signInputs: ISignInputs[] | SignInfo[] = options.keys
			? (function () {
					return options.keys.map((key) =>
						createSignInputsFromImportableEd25519Key(key, document.verificationMethod || [])
					);
				})()
			: await (async function (that: CheqdDIDProvider) {
				return await that.updateIdentifierCompileSignInfos(document, {
						context: context,
						publicKeyHexs: options.publicKeyHexs,
						versionId
				});
			})(this);

		const tx = await sdk.updateDidDocTx(
			signInputs,
			document satisfies DIDDocument,
			'',
			this?.fee,
			undefined,
			versionId,
			{ sdk: sdk } satisfies ISDKContext
		);

		assert(tx.code === 0, `cosmos_transaction: Failed to update DID. Reason: ${tx.rawLog}`);
		// Setup return value
		const identifier: IIdentifier = {
			did: <string>document.id,
			keys: [],
			services: document.service || [],
			provider: document.id.split(':').splice(0, 3).join(':'),
		};;

		if (options.publicKeyHexs) {
			// It means that user
			identifier.keys = await (async function (that: CheqdDIDProvider) {
				const scopedKeys: ManagedKeyInfo[] = [];
				for (const keyRef of options.publicKeyHexs!) {
					try {
						const managedKey = await context.agent.keyManagerGet({
							kid: keyRef
						} satisfies IKeyManagerGetArgs);
						if (managedKey) {
							scopedKeys.push(managedKey);
						}
					} catch (e) {
						debug(`Failed to get key ${keyRef}. Reason: ${e}`);
					}
				}
				return scopedKeys;
			})(this);
		} else {
			// Otherwise - tries to get controllerKeyId from keys or from VerificationMethod
			identifier.keys = options.keys
				? await (async function (that: CheqdDIDProvider) {
						const scopedKeys: ManagedKeyInfo[] = [];
						for (const key of options.keys!) {
							let managedKey: ManagedKeyInfo | undefined;
							try {
								managedKey = await context.agent.keyManagerImport({
									...key,
									kms: options.kms || that.defaultKms,
								} satisfies MinimalImportableKey);
							} catch (e) {
								debug(`Failed to import key ${key.kid}. Reason: ${e}`);

								// construct key, if it failed to import
								managedKey = { ...key, kms: options.kms || that.defaultKms };
							}
							if (managedKey) {
								scopedKeys.push(managedKey);
							}
						}

						return scopedKeys;
				})(this)
				: await (async function (that: CheqdDIDProvider) { 
					const vms: VerificationMethod[] = []
					const controllers = getControllers(document);
					// Otherwise, we need to get verification methods from didDocuments associated with list of controllers
					for (const controller of controllers) {
						// If controller === document.id, then we can to get verification methods from document
						if (controller === document.id && document.verificationMethod) {
                            document.verificationMethod.map((vm) => {
                                vms.push(vm);
                            })
                        } else {
							// Otherwise we need to get verification methods from didDocument associated with controller
							const didDocument = await context.agent.resolveDid({ didUrl: controller }).then((result) => result.didDocument);
							if (!didDocument) {
								throw new Error('[did-provider-cheqd]: updateIdentifier: Error while resolving the DID document for controller DID: ' + controller);
							}
							if (!didDocument.verificationMethod) {
								throw new Error('[did-provider-cheqd]: updateIdentifier: Controller DID document does not contain verification methods');
							}
							didDocument.verificationMethod.map((vm) => {
								vms.push(vm);
							})
						}
					}
					return await that.getKeysFromVerificationMethod(context, vms);
				})(this)
			identifier.controllerKeyId = identifier.keys[0].kid;
		}

		debug('Updated DID', did);

		return identifier;
	}

	async deactivateIdentifier(
		{
			did,
			document,
			options,
		}: {
			did: string;
			document: DIDDocument;
			options: { keys?: TImportableEd25519Key[]; fee?: DidStdFee; versionId?: string };
		},
		context: IContext
	): Promise<boolean> {
		const sdk = await this.getCheqdSDK(options?.fee);
		const versionId = options.versionId || v4();
		const signInputs: ISignInputs[] | SignInfo[] = options.keys
			? (function () {
					return options.keys.map((key) =>
						createSignInputsFromImportableEd25519Key(key, document.verificationMethod || [])
					);
				})()
			: await (async function (that: CheqdDIDProvider) {
					const data = await createMsgDeactivateDidDocPayloadToSign(document, versionId);
					return await that.signPayload(context, data, document.verificationMethod);
				})(this);

		const tx = await sdk.deactivateDidDocTx(
			signInputs,
			document satisfies DIDDocument,
			'',
			this?.fee,
			undefined,
			versionId,
			{ sdk: sdk } satisfies ISDKContext
		);

		assert(tx.code === 0, `cosmos_transaction: Failed to update DID. Reason: ${tx.rawLog}`);

		debug('Deactivated DID', did);

		return true;
	}

	async createResource(
		{
			options,
		}: { options: { payload: ResourcePayload; signInputs?: ISignInputs[]; kms?: string; fee?: DidStdFee } },
		context: IContext
	): Promise<boolean> {
		const sdk = await this.getCheqdSDK(options?.fee);

		const signInputs: ISignInputs[] | SignInfo[] = options.signInputs
			? options.signInputs
			: await (async function (that: CheqdDIDProvider) {
					const did = `did:cheqd:${that.network}:${options.payload.collectionId}`;
					const { didDocument } = await sdk.queryDidDoc(did, { sdk: sdk });

					return await that.signPayload(
						context,
						MsgCreateResourcePayload.encode(MsgCreateResourcePayload.fromPartial(options.payload)).finish(),
						didDocument?.verificationMethod
					);
				})(this);

		const tx = await sdk.createLinkedResourceTx(signInputs, options.payload, '', this?.fee, undefined, {
			sdk: sdk,
		});

		assert(tx.code === 0, `cosmos_transaction: Failed to create Resource. Reason: ${tx.rawLog}`);

		const mapKeyType = (keyType: 'Ed25519' | 'Secp256k1' | 'P256' | undefined): TKeyType | undefined => {
			switch (keyType) {
				case 'Ed25519':
					return 'Ed25519';
				case 'Secp256k1':
					return 'Secp256k1';
				default:
					return undefined;
			}
		};

		if (options.signInputs) {
			const signInput = options.signInputs.filter((input) => mapKeyType(input.keyType) !== undefined);

			const keys: ManagedKeyInfo[] = [];
			for (const input of signInput) {
				let managedKey: ManagedKeyInfo | undefined;
				try {
					// get public key from private key in hex
					const publicKey = toString(
						(await Ed25519.makeKeypair(fromString(input.privateKeyHex, 'hex'))).pubkey,
						'hex'
					);
					managedKey = await context.agent.keyManagerImport({
						kid: publicKey,
						publicKeyHex: publicKey,
						privateKeyHex: input.privateKeyHex,
						type: mapKeyType(input.keyType) as TSupportedKeyType,
						kms: options.kms || this.defaultKms,
					} satisfies MinimalImportableKey);
				} catch (e) {
					debug(`Failed to import key ${input.verificationMethodId}. Reason: ${e}`);
				}
				if (managedKey) {
					keys.push(managedKey);
				}
			}
		}

		debug('Created Resource', options.payload);

		return true;
	}

	async deleteIdentifier(identity: IIdentifier, context: IContext): Promise<boolean> {
		for (const { kid } of identity.keys) {
			await context.agent.keyManagerDelete({ kid });
		}
		return true;
	}

	async addKey(
		{ identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any },
		context: IContext
	): Promise<any> {
		throw Error('CheqdDIDProvider addKey is not supported.');
	}

	async addService(
		{ identifier, service, options }: { identifier: IIdentifier; service: IService; options?: any },
		context: IContext
	): Promise<any> {
		throw Error('CheqdDIDProvider addService is not supported.');
	}

	async removeKey(
		args: {
			identifier: IIdentifier;
			kid: string;
			options?: any;
		},
		context: IContext
	): Promise<any> {
		throw Error('CheqdDIDProvider removeKey is not supported.');
	}

	async removeService(
		args: {
			identifier: IIdentifier;
			id: string;
			options?: any;
		},
		context: IContext
	): Promise<any> {
		throw Error('CheqdDIDProvider removeService is not supported.');
	}

	async transactSendTokens(args: {
		recipientAddress: string;
		amount: Coin;
		memo?: string;
		txBytes?: Uint8Array;
		timeoutMs?: number;
		pollIntervalMs?: number;
	}): Promise<DeliverTxResponse> {
		const sdk = await this.getCheqdSDK(undefined, CheqdDIDProvider.defaultGasPrice);

		if (args?.txBytes) {
			// broadcast txBytes
			const tx = await sdk.signer.broadcastTx(args.txBytes, args?.timeoutMs, args?.pollIntervalMs);

			// assert tx code is 0, in other words, tx succeeded
			assert(tx.code === 0, `cosmos_transaction: Failed to send tokens. Reason: ${tx.rawLog}`);

			// keep log
			debug('Sent tokens', 'txBytes', toString(args.txBytes, 'hex'));

			return tx;
		}

		const tx = await sdk.signer.sendTokens(
			(await (await this.cosmosPayerWallet).getAccounts())[0].address,
			args.recipientAddress,
			[args.amount],
			'auto',
			args.memo
		);

		assert(tx.code === 0, `cosmos_transaction: Failed to send tokens. Reason: ${tx.rawLog}`);

		debug('Sent tokens', args.amount.amount, args.amount.denom, 'to', args.recipientAddress);

		return tx;
	}

	private async signPayload(
		context: IAgentContext<IKeyManager>,
		data: Uint8Array,
		verificationMethod: VerificationMethod[] = []
	): Promise<SignInfo[]> {
		return Promise.all(
			verificationMethod.map(async (method) => {
				const keyRef = extractPublicKeyHex(method);
				return {
					verificationMethodId: method.id,
					signature: base64ToBytes(
						await context.agent.keyManagerSign({
							keyRef,
							data: toString(data, 'hex'),
							encoding: 'hex',
						})
					),
				} satisfies SignInfo;
			})
		);
	}

	private async getKeysFromVerificationMethod(
		context: IAgentContext<IKeyManager>,
		verificationMethod: VerificationMethod[] = []
	): Promise<ManagedKeyInfo[]> {
		return Promise.all(
			verificationMethod.map(async (method) => {
				const kid = extractPublicKeyHex(method);
				return await context.agent.keyManagerGet({ kid });
			})
		).catch((error) => {
			throw new Error(`Failed to sign payload: ${error}`);
		});
	}
}

export async function createMsgCreateDidDocPayloadToSign(
	didPayload: DIDDocument,
	versionId: string
): Promise<Uint8Array> {
	const { protobufVerificationMethod, protobufService } = await DIDModule.validateSpecCompliantPayload(didPayload);
	return MsgCreateDidDocPayload.encode(
		MsgCreateDidDocPayload.fromPartial({
			context: <string[]>didPayload?.['@context'],
			id: didPayload.id,
			controller: <string[]>didPayload.controller,
			verificationMethod: protobufVerificationMethod,
			authentication: <string[]>didPayload.authentication,
			assertionMethod: <string[]>didPayload.assertionMethod,
			capabilityInvocation: <string[]>didPayload.capabilityInvocation,
			capabilityDelegation: <string[]>didPayload.capabilityDelegation,
			keyAgreement: <string[]>didPayload.keyAgreement,
			service: protobufService,
			alsoKnownAs: <string[]>didPayload.alsoKnownAs,
			versionId,
		})
	).finish();
}

export async function createMsgDeactivateDidDocPayloadToSign(
	didPayload: DIDDocument,
	versionId?: string
): Promise<Uint8Array> {
	return MsgDeactivateDidDocPayload.encode(
		MsgDeactivateDidDocPayload.fromPartial({
			id: didPayload.id,
			versionId,
		})
	).finish();
}
