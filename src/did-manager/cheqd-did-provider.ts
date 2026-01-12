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
	FeemarketModule,
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
} from '@veramo/core';
import { AbstractIdentifierProvider } from '@veramo/did-manager';
import { base64ToBytes, extractPublicKeyHex } from '@veramo/utils';
import Debug from 'debug';
import { EnglishMnemonic as _, Bip39, Ed25519, Random } from '@cosmjs/crypto';
import { fromString, toString } from 'uint8arrays';
import { MsgCreateDidDocPayload, MsgDeactivateDidDocPayload, SignInfo } from '@cheqd/ts-proto/cheqd/did/v2/index.js';
import { v4 } from 'uuid';
import {
	CreateCapacityDelegationAuthSignatureResult,
	LitCompatibleCosmosChain,
	LitCompatibleCosmosChains,
	LitNetwork,
	LitNetworks,
	LitProtocol,
	LitContracts,
	MintCapacityCreditsResult,
} from '../dkg-threshold/lit-protocol/v6.js';
import { DkgOptions, IContext } from '../agent/ICheqd.js';
import { getControllers } from '../utils/helpers.js';
import { Secp256k1HdWallet, Secp256k1Wallet } from '@cosmjs/amino';
import { ethers } from 'ethers';

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

export const BitstringStatusPurposeTypes = {
	refresh: 'refresh',
	revocation: 'revocation',
	suspension: 'suspension',
	message: 'message',
} as const;

export const BitstringStatusListResourceType = 'BitstringStatusListCredential';

export const DefaultStatusListEncodings = {
	base64url: 'base64url',
	hex: 'hex',
} as const;

export type DefaultRPCUrl = (typeof DefaultRPCUrls)[keyof typeof DefaultRPCUrls];

export type DefaultRESTUrl = (typeof DefaultRESTUrls)[keyof typeof DefaultRESTUrls];

export type DefaultStatusList2021ResourceType =
	(typeof DefaultStatusList2021ResourceTypes)[keyof typeof DefaultStatusList2021ResourceTypes];

export type DefaultStatusList2021StatusPurposeType =
	(typeof DefaultStatusList2021StatusPurposeTypes)[keyof typeof DefaultStatusList2021StatusPurposeTypes];

export type DefaultStatusListEncoding = (typeof DefaultStatusListEncodings)[keyof typeof DefaultStatusListEncodings];

export type BitstringStatusListPurposeType =
	(typeof BitstringStatusPurposeTypes)[keyof typeof BitstringStatusPurposeTypes];

export type LinkedResource = Omit<MsgCreateResourcePayload, 'data'> & { data?: string };

export type ResourcePayload = Partial<MsgCreateResourcePayload>;

export type StatusList2021ResourcePayload = ResourcePayload & { resourceType: DefaultStatusList2021ResourceType };
export type BitstringStatusListResourcePayload = ResourcePayload & {
	resourceType: typeof BitstringStatusListResourceType;
};

export type TImportableEd25519Key = Required<Pick<IKey, 'publicKeyHex' | 'privateKeyHex'>> & {
	kid: TImportableEd25519Key['publicKeyHex'];
	type: 'Ed25519';
};

export class CheqdProviderError extends Error {
	constructor(
		message: string,
		public readonly errorCode: string
	) {
		super(message);
		this.errorCode = errorCode;
	}
}

export const CheqdProviderErrorCodes = {
	DeactivatedController: 'DeactivatedController',
	UnresolvedDID: 'UnresolvedDID',
	EmptyVerificationMethod: 'EmptyVerificationMethod',
} as const;

export type TPublicKeyEd25519 = Required<Pick<IKey, 'publicKeyHex'>> & {
	kid: TImportableEd25519Key['publicKeyHex'];
	type: 'Ed25519';
};

declare const TImportableEd25519Key: {
	isTImportableEd25519Key(object: object[]): object is TImportableEd25519Key[];
};

export type TSupportedKeyType = 'Ed25519' | 'Secp256k1';

export interface IKeyWithController extends IKey {
	controller?: string;
}

export interface ICheqdIDentifier extends IIdentifier {
	// List of keyRefs which were used for signing the transaction
	controllerKeyRefs?: string[];
	// List of keys which could be used for signing the transaction
	controllerKeys?: IKeyWithController[];
}

export class EnglishMnemonic extends _ {
	static readonly _mnemonicMatcher = /^[a-z]+( [a-z]+)*$/;
}

export class CheqdSignInfoProvider {
	readonly context: IContext;
	signInfos: SignInfo[];
	publicKeyHexs: string[];
	controllers: string[];
	controllerKeys: IKeyWithController[];
	controllerKeyRefs: string[];

	constructor(context: IContext) {
		this.signInfos = [];
		this.publicKeyHexs = [];
		this.controllerKeys = [];
		this.controllerKeyRefs = [];
		this.controllers = [];
		this.context = context;
	}

	setPublicKeyHexs(publicKeyHexs: string[]): void {
		this.publicKeyHexs = publicKeyHexs;
	}

	setSignInfos(signInfos: SignInfo[]): void {
		this.signInfos = signInfos;
	}

	setControllers(controllers: string[]): void {
		this.controllers = controllers;
	}

	getSignInfos(): SignInfo[] {
		return this.signInfos;
	}

	getPublicKeyHexs(): string[] {
		return this.publicKeyHexs;
	}

	getControllerKeys(): IKeyWithController[] {
		return this.controllerKeys;
	}

	getControllerKeyRefs(): string[] {
		return this.controllerKeyRefs;
	}

	getControllerKeysForSigning(): IKeyWithController[] {
		const keys: IKeyWithController[] = [];
		this.controllers.forEach((controller) => {
			const key = this.controllerKeys.find((key) => key.controller === controller);
			if (key) {
				keys.push(key);
			}
		});
		return keys;
	}

	async compileSignInfos(payload: Uint8Array, controllers: string[]): Promise<void> {
		// 1. Iterate over the contollers and for each - get DIDDocument and get the verificationMethodId associated with one of publicKeyHexs
		// 1.1 Iterate over the list of verificationMethods and make the checks:
		// 1.1.1 Iterate over publicKeyHexs and convert each publicKeyHex to the verification Material
		// 1.1.2 If it compares with the one in the verificationMethod, then we have a match and can store the pair of verificationMethodId and publicKeyHex
		// 2. Iterate over the pair of verificationMethodIds and publicKeys and create SignInfo§

		// Setup
		const verificationMethods: VerificationMethod[] = [];

		// Iterate over list of controllers and tries to get the corresponding verificationMethodId associated with one of publicKeyHexs
		for (const controller of controllers) {
			// We need to get here current version of DIDDocument associated with the controller and cannot skip it even if document.id === controller
			// cause in case of remooving verifcation method we need to sign the payload with the old verification method which is on ledger.
			const controllerResolutionResult = await this.context.agent.resolveDid({ didUrl: controller });
			const controllerDidDocument = controllerResolutionResult.didDocument;
			// Check if controller DID document is resolved
			if (!controllerDidDocument) {
				throw new CheqdProviderError(
					'[did-provider-cheqd]: compileSignInfos: Error while resolving the DID document for controller DID: ' +
						controller,
					CheqdProviderErrorCodes.UnresolvedDID
				);
			}
			// Check that controller's DIDDocument is active
			if (controllerResolutionResult.didDocumentMetadata.deactivated) {
				throw new CheqdProviderError(
					`[did-provider-cheqd]: compileSignInfos: DIDDocument associated with controller ${controller} is deactivated`,
					CheqdProviderErrorCodes.DeactivatedController
				);
			}
			// Check if controller DID document contains verification methods
			if (!controllerDidDocument.verificationMethod) {
				throw new CheqdProviderError(
					'[did-provider-cheqd]: compileSignInfos: Controller DID document does not contain verification methods',
					CheqdProviderErrorCodes.EmptyVerificationMethod
				);
			}

			// Iterate over authenticationMethods
			for (const auth of controllerDidDocument.authentication as string[]) {
				if (typeof auth === 'string') {
					let method: VerificationMethod | undefined = controllerDidDocument.verificationMethod?.find(
						(vm) => vm.id === auth
					);

					// If verification method is not found and auth does not start with controller, resolve it
					if (!method && !auth.startsWith(controller)) {
						const resolvedAuthDoc = await this.context.agent
							.resolveDid({ didUrl: auth })
							.then((result) => result.didDocument)
							.catch(() => undefined);

						if (resolvedAuthDoc) {
							method = resolvedAuthDoc.verificationMethod?.find((vm) => vm.id === auth);
						}
					}

					if (method) {
						verificationMethods.push(method);
					}
				}
			}
		}
		// Iterate over verificationMethods
		const signInfos = await Promise.all(
			verificationMethods.map(async (vm) => {
				const keyRef = extractPublicKeyHex(vm).publicKeyHex;
				// Setup key structure for display
				const key = await this.context.agent.keyManagerGet({ kid: keyRef });
				this.controllerKeyRefs.push(keyRef);
				this.controllerKeys.push({ ...key, controller: vm.controller } satisfies IKeyWithController);
				return {
					verificationMethodId: vm.id,
					signature: base64ToBytes(
						await this.context.agent.keyManagerSign({
							keyRef,
							data: toString(payload, 'hex'),
							encoding: 'hex',
						})
					),
				} satisfies SignInfo;
			})
		);
		// Setup signInfos
		this.setSignInfos(signInfos);
	}

	async updateIdentifierCompileSignInfos(
		didDocument: DIDDocument,
		options: {
			versionId?: string;
			publicKeyHexs?: string[];
		}
	): Promise<void> {
		// Steps to solve the issue:
		// 1. Collect list of controllers. The user can remove, append and reqrite the controller.
		//   But we need to send all the signatures, old and news
		// 2. Generate payloads
		// 3. Compile list of signInfos

		// Get current version of DIDDocument
		const actualDIDDocument: DIDResolutionResult = await this.context.agent.resolveDid({ didUrl: didDocument.id });
		if (!actualDIDDocument.didDocument) {
			throw new Error(
				'[did-provider-cheqd]: updateIdentifierSignInfos: Error while resolving the DID document for updating with error: ' +
					actualDIDDocument.didResolutionMetadata.error
			);
		}
		// Compile controllers
		const updatedControllers: string[] = getControllers(didDocument);
		const actualControllers: string[] = getControllers(actualDIDDocument.didDocument);
		const controllers = [...new Set([...updatedControllers, ...actualControllers])];

		// Generate payload
		const versionId = options.versionId || v4();
		const payload = await createMsgCreateDidDocPayloadToSign(didDocument, versionId);

		// Setup controllers. Here it's supposed to be a list of controllers which are associated with the DIDDocument
		this.setControllers(updatedControllers);

		// Setup SignInfos
		await this.compileSignInfos(payload, controllers);

		const signInfos = this.getSignInfos();

		// Iterate over authenticationMethods which are additional in the updatedDidDocument
		const actualAuthentication = actualDIDDocument.didDocument.authentication;
		const additionalAuthentication = didDocument.authentication?.filter((a) => !actualAuthentication?.includes(a));
		const verificationMethods: VerificationMethod[] = [];
		for (const auth of additionalAuthentication as string[]) {
			if (typeof auth === 'string') {
				let method: VerificationMethod | undefined = didDocument.verificationMethod?.find(
					(vm) => vm.id === auth
				);

				// If verification method is not found and auth does not start with controller, resolve it
				if (!method && !auth.startsWith(didDocument.id)) {
					const resolvedAuthDoc = await this.context.agent
						.resolveDid({ didUrl: auth })
						.then((result) => result.didDocument)
						.catch(() => undefined);

					if (resolvedAuthDoc) {
						method = resolvedAuthDoc.verificationMethod?.find((vm) => vm.id === auth);
					}
				}

				if (method) {
					verificationMethods.push(method);
				}
			}
		}

		// Iterate over verificationMethods
		const additionalSignInfos = await Promise.all(
			verificationMethods.map(async (vm) => {
				const keyRef = extractPublicKeyHex(vm).publicKeyHex;
				// Setup key structure for display
				const key = await this.context.agent.keyManagerGet({ kid: keyRef });
				this.controllerKeyRefs.push(keyRef);
				this.controllerKeys.push({ ...key, controller: vm.controller } satisfies IKeyWithController);
				return {
					verificationMethodId: vm.id,
					signature: base64ToBytes(
						await this.context.agent.keyManagerSign({
							keyRef,
							data: toString(payload, 'hex'),
							encoding: 'hex',
						})
					),
				} satisfies SignInfo;
			})
		);

		this.setSignInfos([...signInfos, ...additionalSignInfos]);
	}

	async deactivateIdentifierCompileSignInfos(
		didDocument: DIDDocument,
		options: {
			publicKeyHexs?: string[];
			versionId?: string;
		}
	): Promise<void> {
		// Steps to solve the issue:
		// 1. Collect list of controllers. The user can remove, append and reqrite the controller.
		//   But we need to send all the signatures, old and news
		// Generate payload to sign
		// 3. Compile list of signInfos

		// Get Controllers
		const controllers: string[] = getControllers(didDocument);

		// For did deactivation ledger requires the signature from original DID Document controller
		// So we need to add the controller to the list of controllers
		if (!controllers.includes(didDocument.id)) {
			controllers.push(didDocument.id);
		}

		// Generate payload
		const versionId = options.versionId || v4();
		const payload = await createMsgDeactivateDidDocPayloadToSign(didDocument, versionId);

		// Setup SignInfos
		await this.compileSignInfos(payload, controllers);
	}

	async resourceCreateCompileSignInfos(
		did: string,
		resourcePayload: ResourcePayload,
		options: {
			publicKeyHexs?: string[];
		}
	): Promise<void> {
		// Steps to solve the issue:
		// 1. Collect list of controllers. The user can remove, append and reqrite the controller.
		//   But we need to send all the signatures, old and news
		// Generate payload to sign
		// 3. Compile list of signInfos

		const didDocument = await this.context.agent.resolveDid({ didUrl: did }).then((result) => result.didDocument);
		if (!didDocument) {
			throw new Error(
				'[did-provider-cheqd]: resourceCreateCompileSignInfos: Erro while resolving the DID document for controller DID: ' +
					did
			);
		}
		// Get Controllers
		const controllers: string[] = getControllers(didDocument);

		// For resource creation ledger requires the signature from original DID Document controller
		// So we need to add the controller to the list of controllers
		if (!controllers.includes(did)) {
			controllers.push(did);
		}

		// Generate payload
		const payload = await MsgCreateResourcePayload.encode(
			MsgCreateResourcePayload.fromPartial(resourcePayload)
		).finish();

		// Setup SignInfos
		await this.compileSignInfos(payload, controllers);
	}

	async keysAreInKMS(publicKeys: string[]) {
		for (const keyRef of publicKeys) {
			try {
				await this.context.agent.keyManagerGet({ kid: keyRef });
			} catch (e) {
				return {
					placed: false,
					error: `PublicKey: ${keyRef} is not placed in kms`,
				};
			}
		}
		return {
			placed: true,
		};
	}
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
	private readonly _aminoSigner: Promise<Secp256k1HdWallet | Secp256k1Wallet>;
	private readonly ethereumAuthWallet: ethers.HDNodeWallet | ethers.Wallet;
	public readonly dkgOptions: {
		chain: Extract<LitCompatibleCosmosChain, 'cheqdTestnet' | 'cheqdMainnet'>;
		network: LitNetwork;
	};
	private sdk?: CheqdSDK;
	private fee?: DidStdFee | 'auto' | number;

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
					network: options.dkgOptions.network ? options.dkgOptions.network : LitNetworks.datildev,
				}
			: { chain: DefaultDkgSupportedChains[this.network], network: LitNetworks.datildev };

		if (!options?.cosmosPayerSeed || options.cosmosPayerSeed === '') {
			// generate mnemonic, if not provided
			const mnemonic = Bip39.encode(Random.getBytes(32)).toString();

			// setup wallets - case: cosmos direct payer wallet
			this.cosmosPayerWallet = DirectSecp256k1HdWallet.fromMnemonic(mnemonic);

			// setup wallets - case: ethereum signer wallet
			this.ethereumAuthWallet = ethers.Wallet.fromPhrase(mnemonic);

			// setup wallets - case: amino signer wallet
			this._aminoSigner = Secp256k1HdWallet.fromMnemonic(mnemonic);

			return;
		}

		const isMnemonic = EnglishMnemonic._mnemonicMatcher.test(options.cosmosPayerSeed);

		this.cosmosPayerWallet = isMnemonic
			? DirectSecp256k1HdWallet.fromMnemonic(options.cosmosPayerSeed, { prefix: 'cheqd' })
			: DirectSecp256k1Wallet.fromKey(fromString(options.cosmosPayerSeed.replace(/^0x/, ''), 'hex'), 'cheqd');

		this.ethereumAuthWallet = isMnemonic
			? ethers.Wallet.fromPhrase(options.cosmosPayerSeed)
			: new ethers.Wallet(options.cosmosPayerSeed);

		this._aminoSigner = isMnemonic
			? Secp256k1HdWallet.fromMnemonic(options.cosmosPayerSeed, { prefix: 'cheqd' })
			: Secp256k1Wallet.fromKey(fromString(options.cosmosPayerSeed.replace(/^0x/, ''), 'hex'), 'cheqd');
	}

	async getWalletAccounts(): Promise<readonly AccountData[]> {
		return await (await this.cosmosPayerWallet).getAccounts();
	}

	async getEthereumWalletAccounts(): Promise<readonly AccountData[]> {
		return [
			{
				address: this.ethereumAuthWallet.address,
				pubkey: fromString(this.ethereumAuthWallet.signingKey.publicKey, 'hex'),
				algo: 'secp256k1',
			},
		];
	}

	private async getCheqdSDK(fee?: DidStdFee | 'auto' | number, gasPrice?: GasPrice): Promise<CheqdSDK> {
		if (!this.sdk) {
			const wallet = await this.cosmosPayerWallet.catch(() => {
				throw new Error(`[did-provider-cheqd]: network: ${this.network} valid cosmosPayerSeed is required`);
			});
			const sdkOptions: ICheqdSDKOptions = {
				modules: [
					FeemarketModule as unknown as AbstractCheqdSDKModule,
					DIDModule as unknown as AbstractCheqdSDKModule,
					ResourceModule as unknown as AbstractCheqdSDKModule,
				],
				rpcUrl: this.rpcUrl,
				wallet: wallet,
				gasPrice,
			};

			this.sdk = await createCheqdSDK(sdkOptions);
			this.fee = fee;

			if (this?.fee && typeof this.fee === 'object' && !this?.fee?.payer) {
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
					return await that.signPayload(context, data, options.document);
				})(this);

		const tx = await sdk.createDidDocTx(signInputs, options.document, '', this?.fee, undefined, versionId, undefined, {
			sdk: sdk,
		} satisfies ISDKContext);

		assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`);

		const identifier: ICheqdIDentifier = {
			did: <string>options.document.id,
			keys: [],
			services: options.document.service || [],
			provider: options.document.id.split(':').splice(0, 3).join(':'),
		};

		//* Currently, only one controller key is supported.
		//* We assume that the first key in the list is the controller key.
		//* This is subject to change in the near future.
		identifier.keys = options.keys
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
			: await (async function (that: CheqdDIDProvider) {
					const vmKeys = await that.getKeysFromVerificationMethod(
						context,
						options.document.verificationMethod
					);
					// Setup controllerKeyRefs
					identifier.controllerKeyRefs = vmKeys.map((key) => key.kid);
					// Setup controllerKeys. It's a list of keys to display
					identifier.controllerKeys = vmKeys.map(
						(key) => ({ ...key, controller: options.document.id }) satisfies IKeyWithController
					);
					// Here we are returning all keys associated with the DIDDocument (including keys for controllers)
					// We already compiled it while discovering the verificationMethodIds
					return vmKeys;
				})(this);
		await this.getKeysFromVerificationMethod(context, options.document.verificationMethod);

		const controllerKey: IKey = identifier.keys[0];
		identifier.controllerKeyId = controllerKey.kid;

		debug('Created DID', identifier.did);

		return identifier;
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
				keys?: TImportableEd25519Key[] | TPublicKeyEd25519[];
				versionId?: string;
				fee?: DidStdFee | 'auto' | number;
			};
		},
		context: IContext
	): Promise<ICheqdIDentifier> {
		// Handle input parameters
		const sdk = await this.getCheqdSDK(options?.fee);
		const versionId = options.versionId || v4();
		const keys = options.keys || [];
		const signInfoProvider = new CheqdSignInfoProvider(context);

		// It answers on question what the keys are actually in input
		const areKeysImportable =
			keys.length > 0 &&
			keys.every((key) => {
				return Object.keys(key).includes('privateKeyHex');
			});
		// options.keys may be list of keys with privateKey ibside or just list of publicKeys
		const publicKeyHexs: string[] = areKeysImportable ? [] : keys.map((key) => key.publicKeyHex);

		// Check that publicKeyHexs are placed in kms if the user provides the keys
		const _r = await signInfoProvider.keysAreInKMS(publicKeyHexs);
		if (_r.error) {
			throw Error(`[updateIdentifier]: ${_r.error}`);
		}

		// Check that verificationMethod on changed DIDDocument list exists and not empty
		if (!document.verificationMethod || document.verificationMethod.length === 0) {
			throw new CheqdProviderError(
				'[updateIdentifier]: VerificationMethod should be placed and not be empty',
				CheqdProviderErrorCodes.EmptyVerificationMethod
			);
		}

		const signInputs: ISignInputs[] | SignInfo[] = areKeysImportable
			? (function () {
					// We are sure here that keys are placed
					return options.keys!.map((key) =>
						createSignInputsFromImportableEd25519Key(key, document.verificationMethod || [])
					);
				})()
			: await (async function () {
					await signInfoProvider.updateIdentifierCompileSignInfos(document, {
						publicKeyHexs,
						versionId,
					});
					return signInfoProvider.getSignInfos();
				})();

		debug(
			`[updateIdentifier]: DID: ${did}, VerificationMethodIds for signing: ${signInputs.map((signInput) => signInput.verificationMethodId)}`
		);
		const tx = await sdk.updateDidDocTx(
			signInputs,
			document satisfies DIDDocument,
			'',
			this?.fee,
			undefined,
			versionId,
			undefined,
			{ sdk: sdk } satisfies ISDKContext
		);

		assert(tx.code === 0, `cosmos_transaction: Failed to update DID. Reason: ${tx.rawLog}`);
		// Setup return value
		const identifier: ICheqdIDentifier = {
			did: <string>document.id,
			keys: [],
			services: document.service || [],
			provider: document.id.split(':').splice(0, 3).join(':'),
		};

		// Get keys for updated DIDDocument
		// Here we are importing only the keys which has privateKey field set up
		identifier.keys =
			options.keys && areKeysImportable
				? await (async function (that: CheqdDIDProvider) {
						const scopedKeys: ManagedKeyInfo[] = [];
						for (const key of options.keys!) {
							let managedKey: ManagedKeyInfo | undefined;
							try {
								managedKey = await context.agent.keyManagerImport({
									...(key as TImportableEd25519Key),
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
						// Setup controllerKeyId
						identifier.controllerKeyId = scopedKeys[0].kid;
						return scopedKeys;
					})(this)
				: await (async function (that: CheqdDIDProvider) {
						const vmKeys = await that.getKeysFromVerificationMethod(context, document.verificationMethod);
						// Setup controllerKeyId. It should be asocciated with verificationMethod list
						identifier.controllerKeyId = vmKeys[0].kid;
						// Setup controllerKeyRefs. It's a list of keys which were used for signing the transaction
						identifier.controllerKeyRefs = signInfoProvider.getControllerKeyRefs();
						// Setup controllerKeys. It's a list of keys to display
						identifier.controllerKeys = signInfoProvider.getControllerKeysForSigning();
						// Here we are returning all keys associated with the DIDDocument (including keys for controllers)
						// We already compiled it while discovering the verificationMethodIds
						return vmKeys;
					})(this);

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
			options: {
				keys?: TImportableEd25519Key[] | TPublicKeyEd25519[];
				fee?: DidStdFee | 'auto' | number;
				versionId?: string;
			};
		},
		context: IContext
	): Promise<boolean> {
		const sdk = await this.getCheqdSDK(options?.fee);
		const versionId = options.versionId || v4();
		const keys = options.keys || [];
		// Providr for compiling SignInfos
		const signInfoProvider = new CheqdSignInfoProvider(context);

		// It answers on question what the keys are actually in input
		const areKeysImportable =
			keys.length > 0 &&
			keys.every((key) => {
				return Object.keys(key).includes('privateKeyHex');
			});
		const publicKeyHexs: string[] = areKeysImportable ? [] : keys.map((key) => key.publicKeyHex);

		// Check that publicKeyHexs are placed in kms
		const _r = await signInfoProvider.keysAreInKMS(publicKeyHexs);
		if (_r.error) {
			throw Error(`[deactivateIdentifier]: ${_r.error}`);
		}

		const signInputs: ISignInputs[] | SignInfo[] = areKeysImportable
			? (function () {
					// We are sure here that keys are placed
					return options.keys!.map((key) =>
						createSignInputsFromImportableEd25519Key(key, document.verificationMethod || [])
					);
				})()
			: await (async function () {
					await signInfoProvider.deactivateIdentifierCompileSignInfos(document, {
						publicKeyHexs,
						versionId,
					});
					return signInfoProvider.getSignInfos();
				})();

		debug(
			`[deactivateIdentifier]: DID: ${did}, VerificationMethodIds for signing: ${signInputs.map((signInput) => signInput.verificationMethodId)}`
		);
		const tx = await sdk.deactivateDidDocTx(
			signInputs,
			document satisfies DIDDocument,
			'',
			this?.fee,
			undefined,
			versionId,
			undefined,
			{ sdk: sdk } satisfies ISDKContext
		);

		assert(tx.code === 0, `cosmos_transaction: Failed to update DID. Reason: ${tx.rawLog}`);

		debug('Deactivated DID', did);

		return true;
	}

	async createResource(
		{
			options,
		}: {
			options: {
				payload: ResourcePayload;
				signInputs?: ISignInputs[] | TPublicKeyEd25519[];
				kms?: string;
				fee?: DidStdFee | 'auto' | number;
			};
		},
		context: IContext
	): Promise<boolean> {
		const sdk = await this.getCheqdSDK(options?.fee);
		const signInfoProvider = new CheqdSignInfoProvider(context);
		const inputKeys = options.signInputs || [];

		const areSignInputs =
			inputKeys.length > 0 &&
			inputKeys.every((key) => {
				return Object.keys(key).includes('privateKeyHex');
			});
		// options.signInputs may be list of keys with privateKey ibside or just list of publicKeys
		const publicKeyHexs: string[] = areSignInputs ? [] : inputKeys.map((key) => key.publicKeyHex);

		// Check that publicKeyHexs are placed in kms
		const _r = await signInfoProvider.keysAreInKMS(publicKeyHexs);
		if (_r.error) {
			throw Error(`[updateIdentifier]: ${_r.error}`);
		}

		const signInputs: ISignInputs[] | SignInfo[] = areSignInputs
			? (options.signInputs as ISignInputs[])
			: await (async function (that: CheqdDIDProvider) {
					const did = `did:cheqd:${that.network}:${options.payload.collectionId}`;
					await signInfoProvider.resourceCreateCompileSignInfos(did, options.payload, {
						publicKeyHexs,
					});
					return signInfoProvider.getSignInfos();
				})(this);

		debug(
			`[createResource]: DID: did:cheqd:${this.network}:${options.payload.collectionId} , VerificationMethodIds for signing: ${signInputs.map((signInput) => signInput.verificationMethodId)}`
		);
		const tx = await sdk.createLinkedResourceTx(signInputs, options.payload, '', this?.fee, undefined, undefined, {
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

		if (areSignInputs) {
			const signInput = (inputKeys as ISignInputs[]).filter((input) => mapKeyType(input.keyType) !== undefined);

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

		// poll gas price
		const gasPrice = await sdk.queryGasPrice(args.amount.denom);

		// define fee
		const fee = {
			amount: [
				{
					amount: (Number(gasPrice.price?.amount ?? '0') * 10 ** 9).toString(),
					denom: args.amount.denom,
				},
			],
			gas: '360000',
		} satisfies DidStdFee;

		const tx = await sdk.signer.sendTokens(
			(await (await this.cosmosPayerWallet).getAccounts())[0].address,
			args.recipientAddress,
			[args.amount],
			fee,
			args.memo
		);

		assert(tx.code === 0, `cosmos_transaction: Failed to send tokens. Reason: ${tx.rawLog}`);

		debug('Sent tokens', args.amount.amount, args.amount.denom, 'to', args.recipientAddress);

		return tx;
	}

	async mintCapacityCredit(args: {
		effectiveDays: number;
		requestsPerDay?: number;
		requestsPerSecond?: number;
		requestsPerKilosecond?: number;
	}): Promise<MintCapacityCreditsResult> {
		// instantiate dkg-threshold contract client, in which case lit-protocol is used
		const litContracts = await this.instantiateDkgThresholdContractClient();

		// mint capacity credits
		const result = await litContracts.mintCapacityCredits(args);

		// keep log
		debug(
			'Minted capacity credits',
			result.capacityTokenIdStr,
			'for',
			args.effectiveDays,
			'days',
			'with transaction hash',
			result.rliTxHash,
			'from address',
			this.ethereumAuthWallet.address
		);

		return result;
	}

	async delegateCapacityCredit(args: {
		capacityTokenId: string;
		delegateeAddresses: string[];
		uses: number;
		expiration?: string;
		statement?: string;
	}): Promise<CreateCapacityDelegationAuthSignatureResult> {
		// instantiate dkg-threshold client, in which case lit-protocol is used
		const litProtocol = await this.instantiateDkgThresholdProtocolClient();

		// delegate capacity credits
		const result = await litProtocol.delegateCapacitCredit({
			dAppOwnerWallet:
				this.ethereumAuthWallet instanceof ethers.Wallet
					? this.ethereumAuthWallet
					: new ethers.Wallet(this.ethereumAuthWallet.privateKey),
			capacityTokenId: args.capacityTokenId,
			delegateeAddresses: args.delegateeAddresses,
			uses: args.uses.toString(),
			expiration: args.expiration,
			statement: args.statement,
		});

		// keep log
		debug(
			'Delegated capacity credits',
			args.capacityTokenId,
			'to',
			args.delegateeAddresses.join(', '),
			'with auth signature',
			result.capacityDelegationAuthSig.sig,
			'from address',
			this.ethereumAuthWallet.address
		);

		return result;
	}

	async instantiateDkgThresholdProtocolClient(dkgOptions: DkgOptions = this.dkgOptions): Promise<LitProtocol> {
		const signer = await this._aminoSigner;
		return await LitProtocol.create({
			chain: dkgOptions.chain || this.dkgOptions.chain,
			litNetwork: dkgOptions.network || this.dkgOptions.network,
			cosmosAuthWallet: signer,
		});
	}

	async instantiateDkgThresholdContractClient(
		dkgNetwork: LitNetwork = this.dkgOptions.network
	): Promise<LitContracts> {
		return await LitContracts.create({
			ethereumAuthWallet:
				this.ethereumAuthWallet instanceof ethers.Wallet
					? this.ethereumAuthWallet
					: new ethers.Wallet(this.ethereumAuthWallet.privateKey),
			litNetwork: dkgNetwork,
		});
	}

	private async signPayload(
		context: IAgentContext<IKeyManager>,
		data: Uint8Array,
		didDocument: DIDDocument
	): Promise<SignInfo[]> {
		const controllers = didDocument.controller || [];
		const verificationMethods: VerificationMethod[] = [];
		for (const controller of controllers) {
			let resolvedDocument: DIDDocument | undefined = didDocument;

			if (controller !== didDocument.id) {
				resolvedDocument = await context.agent
					.resolveDid({ didUrl: controller })
					.then((result) => result.didDocument)
					.catch(() => {
						throw new Error(
							`[did-provider-cheqd]: signPayload: Error resolving DID document for controller DID: ${controller}`
						);
					});
			}

			if (!resolvedDocument) {
				throw new Error(`[did-provider-cheqd]: signPayload: Resolved document is undefined for ${controller}`);
			}

			for (const auth of resolvedDocument.authentication as string[]) {
				if (typeof auth === 'string') {
					let method: VerificationMethod | undefined = resolvedDocument.verificationMethod?.find(
						(vm) => vm.id === auth
					);

					// If verification method is not found and auth does not start with controller, resolve it
					if (!method && !auth.startsWith(controller)) {
						const resolvedAuthDoc = await context.agent
							.resolveDid({ didUrl: auth })
							.then((result) => result.didDocument)
							.catch(() => undefined);

						if (resolvedAuthDoc) {
							method = resolvedAuthDoc.verificationMethod?.find((vm) => vm.id === auth);
						}
					}

					if (method) {
						verificationMethods.push(method);
					}
				}
			}
		}

		return Promise.all(
			verificationMethods.map(async (method) => {
				const keyRef = extractPublicKeyHex(method).publicKeyHex;
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
	): Promise<IKeyWithController[]> {
		return Promise.all(
			verificationMethod.map(async (method) => {
				const kid = extractPublicKeyHex(method).publicKeyHex;
				const key = await context.agent.keyManagerGet({ kid });
				return { ...key, controller: method.controller };
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
