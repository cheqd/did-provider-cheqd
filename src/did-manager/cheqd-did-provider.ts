import { CheqdSDK, createCheqdSDK, createSignInputsFromImportableEd25519Key, DIDModule, ICheqdSDKOptions } from '@cheqd/sdk'
import { AbstractCheqdSDKModule } from '@cheqd/sdk/src/modules/_'
import { DidStdFee } from '@cheqd/sdk/src/types'
import { Service, VerificationMethod } from '@cheqd/ts-proto/cheqd/v1/did'
import { MsgCreateDidPayload, MsgUpdateDidPayload } from '@cheqd/ts-proto/cheqd/v1/tx'
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing'
import { assert } from '@cosmjs/utils'
import { DIDDocument } from '@veramo/core/src'
import {
	IIdentifier,
	IKey,
	IService,
	IAgentContext,
	IKeyManager,
	ManagedKeyInfo,
	MinimalImportableKey,
} from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import Debug from 'debug'

const debug = Debug('veramo:did-provider-cheqd')

type IContext = IAgentContext<IKeyManager>

export enum DefaultRPCUrl {
	Mainnet = 'https://rpc.cheqd.net',
	Testnet = 'https://rpc.cheqd.network'
}

export enum NetworkType {
	Mainnet = "mainnet",
	Testnet = "testnet"
}

export type IdentifierPayload = Partial<MsgCreateDidPayload> | Partial<MsgUpdateDidPayload>

export type TImportableEd25519Key = Required<Pick<IKey, 'publicKeyHex' | 'privateKeyHex'>> & { kid: TImportableEd25519Key['publicKeyHex'], type: 'Ed25519' }

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:cheqd` identifiers.
 * @public
*/
export class CheqdDIDProvider extends AbstractIdentifierProvider {
	private defaultKms: string
	private readonly network: NetworkType
	private rpcUrl: string
	private readonly cosmosPayerWallet: Promise<DirectSecp256k1HdWallet>
	private sdk?: CheqdSDK
	private fee?: DidStdFee

	constructor(options: { defaultKms: string, cosmosPayerMnemonic: string, networkType?: NetworkType, rpcUrl?: string }) {
		super()
		this.defaultKms = options.defaultKms
		this.cosmosPayerWallet = DirectSecp256k1HdWallet.fromMnemonic(options.cosmosPayerMnemonic, { prefix: 'cheqd' })
		this.network = options.networkType ? options.networkType : NetworkType.Testnet
		this.rpcUrl = options.rpcUrl ? options.rpcUrl : (this.network === NetworkType.Testnet ? DefaultRPCUrl.Testnet : DefaultRPCUrl.Mainnet)
	}

	/**
	 * 1. Check if SDK
	 * 2. If not, instantiate and pass around
	 * 3. Try creating the DID from the raw payload
	 * 4. Throw if it fails
	 * 5. If it succeeds, print the DID
	 * 6. Store the keys in the key manager
	 * 7. Return the DID implementing IIdentifier
	 */

	private async getCheqdSDK(fee?: DidStdFee): Promise<CheqdSDK> {
		if (!this.sdk) {
			const sdkOptions: ICheqdSDKOptions = {
				// eslint-disable-next-line @typescript-eslint/ban-ts-comment
				// @ts-ignore - No actual type insufficiency here. Learn more about this in the docs.
				modules: [DIDModule as unknown as AbstractCheqdSDKModule],
				rpcUrl: this.rpcUrl,
				wallet: await this.cosmosPayerWallet,
			}

			this.sdk = await createCheqdSDK(sdkOptions)
			this.fee = fee || {
				amount: [
					{
						denom: 'ncheq',
						amount: '5000000'
					}
				],
				gas: '200000',
				payer: (await sdkOptions.wallet.getAccounts())[0].address,
			}
		}
		// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
		return this.sdk!
	}

	async createIdentifier(
		{ kms, options }: { kms?: string; alias?: string, options: { document: IdentifierPayload, keys: TImportableEd25519Key[] } },
		context: IContext,
	): Promise<Omit<IIdentifier, 'provider'>> {
		const sdk = await this.getCheqdSDK()

		const signInputs = options.keys.map(key => createSignInputsFromImportableEd25519Key(key, options.document.verificationMethod ?? []))

		const tx = await sdk.createDidTx(
			signInputs,
			options.document,
			'',
			this.fee || 'auto',
			undefined,
			{ sdk: sdk }
		)

		assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`)

		//* Currently, only one controller key is supported. This is subject to change in the near future.

		const controllerKey: ManagedKeyInfo = await context.agent.keyManagerImport({
			...options.keys[0],
			kms: kms || this.defaultKms,
		} as MinimalImportableKey)

		const _keys = await Promise.all(options.keys.slice(1).map(async key => await context.agent.keyManagerImport({ ...key, kms: kms || this.defaultKms })))

		const identifier: IIdentifier = {
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			did: options.document.id!,
			controllerKeyId: controllerKey.kid,
			keys: [controllerKey, ..._keys],
			services: options.document.service || [],
			provider: 'cheqd',
		}

		debug('Created DID', identifier.did)

		return identifier
	}

	// TODO: Add client side diff calculation using the resolver & SDK helper functions.
	//* This will allow for better accuracy and predictability of `updateIdentifier` race conditions.
	async updateIdentifier(
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		{ did, document, options}: { did: string, document: Partial<DIDDocument>, options: { kms: string, keys: TImportableEd25519Key[] } },
		context: IContext,
	): Promise<IIdentifier> {
		const sdk = await this.getCheqdSDK()

		const signInputs = options.keys.map(key => createSignInputsFromImportableEd25519Key(key, document.verificationMethod as unknown as VerificationMethod[] ?? []))

		const tx = await sdk.updateDidTx(
			signInputs,
			document as Partial<IdentifierPayload>,
			'',
			this.fee || 'auto',
			undefined,
			{ sdk: sdk }
		)

		assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`)

		//* Currently, only one controller key is supported. This is subject to change in the near future.

		const controllerKey: ManagedKeyInfo = await context.agent.keyManagerImport({
			...options.keys[0],
			kms: options.kms || this.defaultKms,
		} as MinimalImportableKey)

		const _keys = await Promise.all(options.keys.slice(1).map(async key => await context.agent.keyManagerImport({ ...key, kms: options.kms || this.defaultKms })))

		const identifier: IIdentifier = {
			// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
			did: document.id!,
			controllerKeyId: controllerKey.kid,
			keys: [controllerKey, ..._keys],
			services: document.service as unknown as Service[] || [],
			provider: 'cheqd',
		}

		debug('Updated DID', did)

		return identifier
	}

	async deleteIdentifier(
		identity: IIdentifier,
		context: IContext,
	): Promise<boolean> {
		for (const { kid } of identity.keys) {
			await context.agent.keyManagerDelete({ kid })
		}
		return true
	}

	async addKey(
		{
			//  eslint-disable-next-line @typescript-eslint/no-unused-vars
			identifier,
			//  eslint-disable-next-line @typescript-eslint/no-unused-vars
			key,
			//  eslint-disable-next-line @typescript-eslint/no-unused-vars
			options,
			//  eslint-disable-next-line @typescript-eslint/no-explicit-any
		}: { identifier: IIdentifier; key: IKey; options?: any },
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		context: IContext,
		//  eslint-disable-next-line @typescript-eslint/no-explicit-any
	): Promise<any> {
		throw Error('CheqdDIDProvider addKey not supported yet.')
	}

	async addService(
		{
			//  eslint-disable-next-line @typescript-eslint/no-unused-vars
			identifier,
			//  eslint-disable-next-line @typescript-eslint/no-unused-vars
			service,
			//  eslint-disable-next-line @typescript-eslint/no-unused-vars
			options,
			//  eslint-disable-next-line @typescript-eslint/no-explicit-any
		}: { identifier: IIdentifier; service: IService; options?: any },
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		context: IContext,
		//  eslint-disable-next-line @typescript-eslint/no-explicit-any
	): Promise<any> {
		throw Error('CheqdDIDProvider addService not supported yet.')
	}

	async removeKey(
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		args: {
			identifier: IIdentifier;
			kid: string;
			//  eslint-disable-next-line @typescript-eslint/no-explicit-any
			options?: any
		},
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		context: IContext,
		//  eslint-disable-next-line @typescript-eslint/no-explicit-any
	): Promise<any> {
		throw Error('CheqdDIDProvider removeKey not supported yet.')
	}

	async removeService(
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		args: {
			identifier: IIdentifier;
			id: string;
			//  eslint-disable-next-line @typescript-eslint/no-explicit-any
			options?: any
		},
		//  eslint-disable-next-line @typescript-eslint/no-unused-vars
		context: IContext,
		//  eslint-disable-next-line @typescript-eslint/no-explicit-any
	): Promise<any> {
		throw Error('CheqdDIDProvider removeService not supported yet.')
	}
}
