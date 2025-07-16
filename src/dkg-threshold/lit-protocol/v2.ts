import { OfflineAminoSigner, Secp256k1HdWallet, StdSignDoc } from '@cosmjs/amino';
import { toString } from 'uint8arrays/to-string';
import { sha256 } from '@cosmjs/crypto';
import { LitNodeClientNodeJs, LitNodeClient, encryptString } from '@lit-protocol/lit-node-client-v2';
import { decryptString } from '@lit-protocol/encryption-v2';
import { JsonSaveEncryptionKeyRequest } from '@lit-protocol/types-v2';
import { randomBytes } from '../../utils/helpers.js';
import { isBrowser, isNode } from '../../utils/env.js';
import { v4 } from 'uuid';
import { LitProtocolDebugEnabled } from '../../utils/constants.js';

export type EncryptionResultV2 = {
	encryptedString: Blob;
	encryptedSymmetricKey: string;
	symmetricKey?: Uint8Array;
};
export type AuthSignatureV2 = {
	sig: string;
	derivedVia: 'cosmos.signArbitrary';
	signedMessage: string;
	address: string;
};
export type CosmosAuthSignatureV2 = {
	cosmos: AuthSignatureV2;
};
export type CosmosReturnValueTestV2 = {
	key: string;
	comparator: string;
	value: string;
};
export type CosmosAccessControlConditionV2 = {
	conditionType: 'cosmos';
	path: string;
	chain: LitCompatibleCosmosChainV2;
	method?: string;
	parameters?: string[];
	returnValueTest: CosmosReturnValueTestV2;
};
export type SaveEncryptionKeyArgs = {
	unifiedAccessControlConditions: CosmosAccessControlConditionV2[];
	symmetricKey: CryptoKey;
	authSig: CosmosAuthSignatureV2;
	chain: string;
};
export type GetEncryptionKeyArgs = {
	unifiedAccessControlConditions: CosmosAccessControlConditionV2[];
	toDecrypt: string;
	authSig: CosmosAuthSignatureV2;
	chain: string;
};
export type EncryptStringMethodResultV2 = { encryptedString: Blob; symmetricKey: Uint8Array };
export type DecryptStringMethodResultV2 = string;
export type EncryptStringMethodV2 = (str: string) => Promise<EncryptStringMethodResultV2>;
export type DecryptStringMethod = (
	encryptedString: Blob,
	symmetricKey: Uint8Array
) => Promise<DecryptStringMethodResultV2>;
export type LitNetworkV2 = (typeof LitNetworksV2)[keyof typeof LitNetworksV2];
export type LitCompatibleCosmosChainV2 = (typeof LitCompatibleCosmosChainsV2)[keyof typeof LitCompatibleCosmosChainsV2];
export type LitProtocolOptionsV2 = {
	cosmosAuthWallet: Secp256k1HdWallet;
	litNetwork?: LitNetworkV2;
	chain?: LitCompatibleCosmosChainV2;
};
export type TxNonceFormatV2 = (typeof TxNonceFormatsV2)[keyof typeof TxNonceFormatsV2];

export const LitNetworksV2 = {
	jalapeno: 'jalapeno',
	serrano: 'serrano',
	localhost: 'localhost',
	custom: 'custom',
} as const;
export const LitCompatibleCosmosChainsV2 = {
	cosmos: 'cosmos',
	cheqdMainnet: 'cheqdMainnet',
	cheqdTestnet: 'cheqdTestnet',
} as const;
export const TxNonceFormatsV2 = { entropy: 'entropy', uuid: 'uuid', timestamp: 'timestamp' } as const;

export class LitProtocolV2 {
	client: LitNodeClientNodeJs | LitNodeClient;
	litNetwork: LitNetworkV2 = LitNetworksV2.serrano;
	chain: LitCompatibleCosmosChainV2 = LitCompatibleCosmosChainsV2.cheqdTestnet;
	private readonly cosmosAuthWallet: Secp256k1HdWallet;

	private constructor(options: LitProtocolOptionsV2) {
		// validate options
		if (options.litNetwork && !Object.values(LitNetworksV2).includes(options.litNetwork))
			throw new Error(`[did-provider-cheqd]: lit-protocol: Invalid LitNetworkV2: ${options.litNetwork}`);
		if (options.chain && !Object.values(LitCompatibleCosmosChainsV2).includes(options.chain))
			throw new Error(`[did-provider-cheqd]: lit-protocol: Invalid LitCompatibleCosmosChainV2: ${options.chain}`);

		// set options
		if (options.litNetwork) this.litNetwork = options.litNetwork;
		if (options.chain) this.chain = options.chain;
		this.cosmosAuthWallet = options.cosmosAuthWallet;

		// set client as per environment
		this.client = (function (that: LitProtocolV2) {
			if (isNode) return new LitNodeClientNodeJs({ litNetwork: that.litNetwork, debug: LitProtocolDebugEnabled });
			if (isBrowser) return new LitNodeClient({ litNetwork: that.litNetwork, debug: LitProtocolDebugEnabled });
			throw new Error('[did-provider-cheqd]: lit-protocol: Unsupported runtime environment');
		})(this);
	}

	async connect(): Promise<void> {
		return await this.client.connect();
	}

	async encrypt(
		secret: string,
		unifiedAccessControlConditions: NonNullable<JsonSaveEncryptionKeyRequest['unifiedAccessControlConditions']>,
		returnSymmetricKey = false
	): Promise<EncryptionResultV2> {
		const authSig = await LitProtocolV2.generateAuthSignature(this.cosmosAuthWallet);
		const { encryptedString, symmetricKey } = (await encryptString(
			secret as string
		)) as EncryptStringMethodResultV2;
		const encryptedSymmetricKey = await this.client.saveEncryptionKey({
			unifiedAccessControlConditions,
			symmetricKey,
			authSig: authSig,
			chain: this.chain,
		});

		return {
			encryptedString,
			encryptedSymmetricKey: toString(encryptedSymmetricKey, 'hex'),
			symmetricKey: returnSymmetricKey ? symmetricKey : undefined,
		};
	}

	async decrypt(
		encryptedString: Blob,
		encryptedSymmetricKey: string,
		unifiedAccessControlConditions: NonNullable<JsonSaveEncryptionKeyRequest['unifiedAccessControlConditions']>
	): Promise<string> {
		const authSig = await LitProtocolV2.generateAuthSignature(this.cosmosAuthWallet);
		const symmetricKey = await this.client.getEncryptionKey({
			unifiedAccessControlConditions,
			toDecrypt: encryptedSymmetricKey,
			authSig: authSig,
			chain: this.chain,
		});
		return (await decryptString(encryptedString, symmetricKey)) as DecryptStringMethodResultV2;
	}

	static async encryptDirect(secret: string): Promise<EncryptStringMethodResultV2> {
		const { encryptedString, symmetricKey } = (await encryptString(
			secret as string
		)) as EncryptStringMethodResultV2;
		return {
			encryptedString,
			symmetricKey,
		};
	}

	static async decryptDirect(encryptedString: Blob, symmetricKey: Uint8Array): Promise<DecryptStringMethodResultV2> {
		return (await decryptString(encryptedString, symmetricKey)) as DecryptStringMethodResultV2;
	}

	static async create(options: Partial<LitProtocolOptionsV2>): Promise<LitProtocolV2> {
		// instantiate underlying cosmos auth wallet
		if (!options.cosmosAuthWallet)
			options.cosmosAuthWallet = await Secp256k1HdWallet.generate(24, {
				prefix: await LitProtocolV2.getCosmosWalletPrefix(options?.chain),
			});

		// validate top-level options chain
		if (!options?.chain) options.chain = LitCompatibleCosmosChainsV2.cheqdTestnet;

		// validate top-level options litNetwork
		if (!options?.litNetwork) options.litNetwork = LitNetworksV2.serrano;

		const litProtocol = new LitProtocolV2(options as LitProtocolOptionsV2);
		await litProtocol.connect();
		return litProtocol;
	}

	static async getCosmosWalletPrefix(chain?: LitCompatibleCosmosChainV2): Promise<string> {
		switch (chain) {
			case LitCompatibleCosmosChainsV2.cosmos:
				return 'cosmos';
			case LitCompatibleCosmosChainsV2.cheqdMainnet:
				return 'cheqd';
			case LitCompatibleCosmosChainsV2.cheqdTestnet:
				return 'cheqd';
			default:
				return 'cheqd';
		}
	}

	static async generateAuthSignature(wallet: OfflineAminoSigner): Promise<AuthSignatureV2> {
		const signerAddress = (await wallet.getAccounts())[0].address;
		const signData = await LitProtocolV2.generateSignData();
		const signDoc = await LitProtocolV2.generateSignDoc(signerAddress, signData);
		const result = await wallet.signAmino(signerAddress, signDoc);
		return {
			address: signerAddress,
			derivedVia: 'cosmos.signArbitrary',
			sig: result.signature.signature,
			signedMessage: toString(sha256(new TextEncoder().encode(JSON.stringify(signDoc))), 'hex'), // <-- hex encoded sha256 hash of the json stringified signDoc
		};
	}

	static async generateSignDoc(address: string, data: Uint8Array): Promise<StdSignDoc> {
		return {
			account_number: '0',
			chain_id: '',
			fee: {
				amount: [],
				gas: '0',
			},
			memo: '',
			msgs: [
				{
					type: 'sign/MsgSignData',
					value: {
						data: toString(data, 'base64'),
						signer: address,
					},
				},
			],
			sequence: '0',
		}; // <-- should be sorted alphabetically
	}

	static async generateSignData(): Promise<Uint8Array> {
		return new TextEncoder().encode(`I am creating an account to use Lit Protocol at 2023-02-21T16:40:15.305Z`); // <-- lit nodes search for this string in the signData
	}

	static async generateTxNonce(format?: TxNonceFormatV2, entropyLength?: number): Promise<string> {
		switch (format) {
			case TxNonceFormatsV2.entropy:
				return toString(await randomBytes(entropyLength || 64), 'hex');
			case TxNonceFormatsV2.uuid:
				return v4();
			case TxNonceFormatsV2.timestamp:
				return new Date().toISOString();
			default:
				return v4();
		}
	}

	static async generateCosmosAccessControlConditionBalance(
		returnValueTest: CosmosReturnValueTestV2,
		chain: LitCompatibleCosmosChainV2 = LitCompatibleCosmosChainsV2.cheqdTestnet,
		address = ':userAddress'
	): Promise<CosmosAccessControlConditionV2> {
		return {
			conditionType: 'cosmos',
			path: `/cosmos/bank/v1beta1/balances/${address}`,
			chain,
			returnValueTest,
		};
	}

	static async generateCosmosAccessControlConditionTransactionMemo(
		returnValueTest: CosmosReturnValueTestV2,
		amount: string,
		sender: string,
		recipient = ':userAddress',
		chain: LitCompatibleCosmosChainV2 = LitCompatibleCosmosChainsV2.cheqdTestnet
	): Promise<CosmosAccessControlConditionV2> {
		return {
			conditionType: 'cosmos',
			path: `/cosmos/tx/v1beta1/txs?query=transfer.recipient='${recipient}' AND transfer.sender='${sender}' AND transfer.amount='${amount}'&order_by=2`,
			chain,
			returnValueTest,
		};
	}

	static async generateCosmosAccessControlConditionInverseTimelock(
		returnValueTest: CosmosReturnValueTestV2,
		amount: string,
		recipient = ':userAddress',
		blockHeight = 'latest',
		chain: LitCompatibleCosmosChainV2 = LitCompatibleCosmosChainsV2.cheqdTestnet
	): Promise<CosmosAccessControlConditionV2> {
		return {
			conditionType: 'cosmos',
			path: `/cosmos/tx/v1beta1/txs?query=transfer.recipient='${recipient}' AND transfer.amount='${amount}'&order_by=2&pagination.limit=1`,
			chain,
			method: 'timelock',
			parameters: [blockHeight],
			returnValueTest,
		};
	}
}
