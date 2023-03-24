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
	IContext as ISDKContext
} from '@cheqd/sdk'
import { MsgCreateResourcePayload } from '@cheqd/ts-proto/cheqd/resource/v2'
import { 
	DirectSecp256k1HdWallet,
	DirectSecp256k1Wallet
} from '@cosmjs/proto-signing'
import { assert } from '@cosmjs/utils'
import { DIDDocument } from 'did-resolver'
import {
	IIdentifier,
	IKey,
	IService,
	IAgentContext,
	IKeyManager,
	ManagedKeyInfo,
	MinimalImportableKey,
	TKeyType,
} from '@veramo/core'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import { extractPublicKeyHex } from '@veramo/utils'
import Debug from 'debug'
import {
	EnglishMnemonic as _,
	Ed25519
} from '@cosmjs/crypto'
import {
	fromString,
	toString
} from 'uint8arrays'
import { MsgCreateDidDocPayload, MsgDeactivateDidDocPayload, SignInfo } from '@cheqd/ts-proto/cheqd/did/v2'
import { v4 } from 'uuid'

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

export type LinkedResource = Omit<MsgCreateResourcePayload, 'data'> & { data?: string }

export type ResourcePayload = Partial<MsgCreateResourcePayload>

export type TImportableEd25519Key = Required<Pick<IKey, 'publicKeyHex' | 'privateKeyHex'>> & { kid: TImportableEd25519Key['publicKeyHex'], type: 'Ed25519' }

declare const TImportableEd25519Key: {
    isTImportableEd25519Key(object: Object[]): object is TImportableEd25519Key[];
}

export type TSupportedKeyType = 'Ed25519' | 'Secp256k1'

export class EnglishMnemonic extends _ {
	static readonly _mnemonicMatcher = /^[a-z]+( [a-z]+)*$/;
}

async function createMsgCreateDidDocPayloadToSign(didPayload: DIDDocument, versionId: string) {
  const { protobufVerificationMethod, protobufService } = await DIDModule.validateSpecCompliantPayload(didPayload)
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
  ).finish()
}

function createMsgDeactivateDidDocPayloadToSign(didPayload: DIDDocument, versionId?: string) {
  return MsgDeactivateDidDocPayload.encode(
    MsgDeactivateDidDocPayload.fromPartial({
      id: didPayload.id,
      versionId,
    })
  ).finish()
}

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:cheqd` identifiers.
 * @public
*/
export class CheqdDIDProvider extends AbstractIdentifierProvider {
	private defaultKms: string
	public readonly network: NetworkType
	private rpcUrl: string
	private readonly cosmosPayerWallet: Promise<DirectSecp256k1HdWallet | DirectSecp256k1Wallet>
	private sdk?: CheqdSDK
	private fee?: DidStdFee

	constructor(options: { defaultKms: string, cosmosPayerSeed: string, networkType?: NetworkType, rpcUrl?: string }) {
		super()
		this.defaultKms = options.defaultKms
		this.network = options.networkType ? options.networkType : NetworkType.Testnet
		this.rpcUrl = options.rpcUrl ? options.rpcUrl : (this.network === NetworkType.Testnet ? DefaultRPCUrl.Testnet : DefaultRPCUrl.Mainnet)

		if (!options?.cosmosPayerSeed || options.cosmosPayerSeed === '') {
			this.cosmosPayerWallet = DirectSecp256k1HdWallet.generate()
			return
		}
		this.cosmosPayerWallet = EnglishMnemonic._mnemonicMatcher.test(options.cosmosPayerSeed)
			? DirectSecp256k1HdWallet.fromMnemonic(options.cosmosPayerSeed, { prefix: 'cheqd' })
			: DirectSecp256k1Wallet.fromKey(
				fromString(
					options.cosmosPayerSeed.replace(/^0x/, ''),
					'hex'
				),
				'cheqd'
			)
	}

	private async getCheqdSDK(fee?: DidStdFee): Promise<CheqdSDK> {
		if (!this.sdk) {
			const wallet = await this.cosmosPayerWallet.catch(() => {
				throw new Error(`[did-provider-cheqd]: network: ${this.network} valid cosmosPayerSeed is required`)
			})
			const sdkOptions: ICheqdSDKOptions = {
				modules: [DIDModule as unknown as AbstractCheqdSDKModule, ResourceModule as unknown as AbstractCheqdSDKModule],
				rpcUrl: this.rpcUrl,
				wallet: wallet,
			}

			this.sdk = await createCheqdSDK(sdkOptions)
			this.fee = fee

			if (this?.fee && !this?.fee?.payer) {
				const feePayer = (await (await this.cosmosPayerWallet).getAccounts())[0].address
				this.fee.payer = feePayer
			}
		}
		return this.sdk!
	}

	async createIdentifier(
		{ kms, options }: { kms?: string; alias?: string, options: { document: DIDDocument, keys?: TImportableEd25519Key[], versionId?: string, fee?: DidStdFee } },
		context: IContext,
	): Promise<Omit<IIdentifier, 'provider'>> {
		const sdk = await this.getCheqdSDK(options?.fee)

        let signInputs : ISignInputs[] | SignInfo[]
        if(options.keys) {
		  signInputs = options.keys.map(key => createSignInputsFromImportableEd25519Key(key, options.document.verificationMethod ?? []))
        } else {
          const data = await createMsgCreateDidDocPayloadToSign(options.document, options.versionId || v4())
          signInputs = await this.signPayload(context, data, options.document.verificationMethod)
        }

		const tx = await sdk.createDidDocTx(
			signInputs,
			options.document,
			'',
			this?.fee,
			undefined,
			options?.versionId,
			{ sdk: sdk } as ISDKContext,
		)

		assert(tx.code === 0, `cosmos_transaction: Failed to create DID. Reason: ${tx.rawLog}`)

		//* Currently, only one controller key is supported.
		//* We assume that the first key in the list is the controller key.
		//* This is subject to change in the near future.
        let keys: ManagedKeyInfo[] = []
        if(options.keys) {
            for (const key of options.keys) {
                let managedKey: ManagedKeyInfo | undefined
                try {
                    managedKey = await context.agent.keyManagerImport({
                        ...key,
                        kms: kms || this.defaultKms,
                    } as MinimalImportableKey)
                } catch (e) {
                    debug(`Failed to import key ${key.kid}. Reason: ${e}`)
                }
                if (managedKey) {
                    keys.push(managedKey)
                }
            }
        } else {
            keys = await this.getKeysFromVerificationMethod(context, options.document.verificationMethod)  
        }

        const controllerKey: IKey = keys[0]
		const identifier: IIdentifier = {
			did: <string>options.document.id,
			controllerKeyId: controllerKey.kid,
			keys: [controllerKey, ...keys],
			services: options.document.service || [],
			provider: 'cheqd',
		}

		debug('Created DID', identifier.did)

		return identifier
	}

	async updateIdentifier(
		{ did, document, options}: { did: string, document: DIDDocument, options: { kms: string, keys?: TImportableEd25519Key[], versionId?: string, fee?: DidStdFee } },
		context: IContext,
	): Promise<IIdentifier> {
		const sdk = await this.getCheqdSDK(options?.fee)

        let signInputs : ISignInputs[] | SignInfo[]
        if(options.keys) {
		  signInputs = options.keys.map(key => createSignInputsFromImportableEd25519Key(key, document.verificationMethod ?? []))
        } else {
          const data = await createMsgCreateDidDocPayloadToSign(document, options.versionId || v4())
          signInputs = await this.signPayload(context, data, document.verificationMethod)
        }

		const tx = await sdk.updateDidDocTx(
			signInputs,
			document as DIDDocument,
			'',
			this?.fee,
			undefined,
			options?.versionId,
			{ sdk: sdk } as ISDKContext,
		)

		assert(tx.code === 0, `cosmos_transaction: Failed to update DID. Reason: ${tx.rawLog}`)

		//* Currently, only one controller key is supported.
		//* We assume that the first key in the list is the controller key.
		//* This is subject to change in the near future.
        let keys: ManagedKeyInfo[] = []
        if(options.keys) {
            const keys: ManagedKeyInfo[] = []
            for (const key of options.keys) {
                let managedKey: ManagedKeyInfo | undefined
                try {
                    managedKey = await context.agent.keyManagerImport({
                        ...key,
                        kms: options.kms || this.defaultKms,
                    } as MinimalImportableKey)
                } catch (e) {
                    debug(`Failed to import key ${key.kid}. Reason: ${e}`)
                }
                if (managedKey) {
                    keys.push(managedKey)
                }
            }
        } else {
            keys = await this.getKeysFromVerificationMethod(context, document.verificationMethod)  
        }

		const controllerKey = keys[0]

		const identifier: IIdentifier = {
			did: <string>document.id,
			controllerKeyId: controllerKey.kid,
			keys: [controllerKey, ...keys],
			services: document.service || [],
			provider: 'cheqd',
		}

		debug('Updated DID', did)

		return identifier
	}

	async deactivateIdentifier(
		{ did, document, options}: { did: string, document: DIDDocument, options: { keys?: TImportableEd25519Key[], fee?: DidStdFee, versionId?: string } },
		context: IContext,
	): Promise<boolean> {
		const sdk = await this.getCheqdSDK(options?.fee)

        let signInputs : ISignInputs[] | SignInfo[]
        if(options.keys) {
		  signInputs = options.keys.map(key => createSignInputsFromImportableEd25519Key(key, document.verificationMethod ?? []))
        } else {
          const data = createMsgDeactivateDidDocPayloadToSign(document, options.versionId || v4())
          signInputs = await this.signPayload(context, data, document.verificationMethod)
        }

		const tx = await sdk.deactivateDidDocTx(
			signInputs,
			document as DIDDocument,
			'',
			this?.fee,
			undefined,
			undefined,
			{ sdk: sdk } as ISDKContext,
		)

		assert(tx.code === 0, `cosmos_transaction: Failed to update DID. Reason: ${tx.rawLog}`)

		debug('Deactivated DID', did)

		return true
	}

	async createResource(
		{ options }: { options: { payload: ResourcePayload, signInputs?: ISignInputs[], kms?: string, fee?: DidStdFee } },
		context: IContext,
	): Promise<boolean> {
		const sdk = await this.getCheqdSDK(options?.fee)

        let signInputs: ISignInputs[] | SignInfo[]
        if(!options.signInputs) {
            const did = `did:cheqd:${this.network}:${options.payload.collectionId}`
            const { didDocument } = await sdk.queryDidDoc(
                did,
                { sdk: sdk }
            )

            signInputs = await this.signPayload(
                context, 
                MsgCreateResourcePayload.encode(MsgCreateResourcePayload.fromPartial(options.payload)).finish(),
                didDocument?.verificationMethod    
            )
        } else {
            signInputs = options.signInputs
        }

		const tx = await sdk.createLinkedResourceTx(
			signInputs,
			options.payload,
			'',
			this?.fee,
			undefined,
			{ sdk: sdk }
		)

		assert(tx.code === 0, `cosmos_transaction: Failed to create Resource. Reason: ${tx.rawLog}`)

		const mapKeyType = (keyType: "Ed25519" | "Secp256k1" | "P256" | undefined): TKeyType | undefined => {
			switch (keyType) {
				case "Ed25519": return "Ed25519"
				case "Secp256k1": return "Secp256k1"
				default: return undefined
			}
		}

        if(options.signInputs) {
            const signInput = options.signInputs.filter(input => mapKeyType(input.keyType) !== undefined)

            const keys: ManagedKeyInfo[] = []
            for (const input of signInput) {
                let managedKey: ManagedKeyInfo | undefined
                try {
                    // get public key from private key in hex
                    const publicKey = toString((await Ed25519.makeKeypair(fromString(input.privateKeyHex, 'hex'))).pubkey, 'hex')
                    managedKey = await context.agent.keyManagerImport({
                        kid: publicKey,
                        publicKeyHex: publicKey,
                        privateKeyHex: input.privateKeyHex,
                        type: mapKeyType(input.keyType) as TSupportedKeyType,
                        kms: options.kms || this.defaultKms,
                    } as MinimalImportableKey)
                } catch (e) {
                    debug(`Failed to import key ${input.verificationMethodId}. Reason: ${e}`)
                }
                if (managedKey) {
                    keys.push(managedKey)
                }
            }
        }

		debug('Created Resource', options.payload)

		return true
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
			identifier,
			key,
			options,
		}: { identifier: IIdentifier; key: IKey; options?: any },
		context: IContext,
	): Promise<any> {
		throw Error('CheqdDIDProvider addKey is not supported.')
	}

	async addService(
		{
			identifier,
			service,
			options,
		}: { identifier: IIdentifier; service: IService; options?: any },
		context: IContext,
	): Promise<any> {
		throw Error('CheqdDIDProvider addService is not supported.')
	}

	async removeKey(
		args: {
			identifier: IIdentifier;
			kid: string;
			options?: any
		},
		context: IContext,
	): Promise<any> {
		throw Error('CheqdDIDProvider removeKey is not supported.')
	}

	async removeService(
		args: {
			identifier: IIdentifier;
			id: string;
			options?: any
		},
		context: IContext,
	): Promise<any> {
		throw Error('CheqdDIDProvider removeService is not supported.')
	}

    private async signPayload(context: IAgentContext<IKeyManager>, data: Uint8Array, verificationMethod: VerificationMethod[] = []): Promise<SignInfo[]> {
        return Promise.all(
          verificationMethod.map(async (method)=>{
            const keyRef = extractPublicKeyHex(method)
            return {
              verificationMethodId: method.id,
              signature: fromString(await context.agent.keyManagerSign({
                keyRef,
                data: toString(data, 'hex'),
                encoding: 'hex'
              }))
            } satisfies SignInfo
          })
        )
    }

    private async getKeysFromVerificationMethod(context: IAgentContext<IKeyManager>, verificationMethod: VerificationMethod[] = []): Promise<ManagedKeyInfo[]> {
        return Promise.all(
          verificationMethod.map(async (method)=>{
            const kid = extractPublicKeyHex(method)
            return await context.agent.keyManagerGet({kid})
          })
        ).catch((error)=>{
            throw new Error(`Failed to sign payload: ${error}`)
        })
    }
}
