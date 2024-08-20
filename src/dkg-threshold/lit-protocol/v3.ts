import { OfflineAminoSigner, Secp256k1HdWallet, StdSignDoc } from '@cosmjs/amino';
import { toString } from 'uint8arrays/to-string';
import { sha256 } from '@cosmjs/crypto';
import { LitNodeClientNodeJs, LitNodeClient } from '@lit-protocol/lit-node-client-v3';
import { DecryptResponse, EncryptResponse, UnifiedAccessControlConditions } from '@lit-protocol/types-v3';
import { generateSymmetricKey, randomBytes } from '../../utils/helpers.js';
import { isBrowser, isNode } from '../../utils/env.js';
import { v4 } from 'uuid';
import { fromString } from 'uint8arrays';
import { LitProtocolDebugEnabled } from '../../utils/constants.js';

export type ThresholdEncryptionResult = {
	encryptedString: Uint8Array;
	stringHash: string;
};
export type SymmetricEncryptionResult = {
	encryptedString: Blob;
	stringHash: string;
	symmetricKey: Uint8Array;
};
export type AuthSignature = {
	sig: string;
	derivedVia: 'cosmos.signArbitrary';
	signedMessage: string;
	address: string;
};
export type CosmosAuthSignature = {
	cosmos: AuthSignature;
};
export type CosmosReturnValueTest = {
	key: string;
	comparator: string;
	value: string;
};
export interface CosmosAccessControlCondition {
	conditionType: 'cosmos';
	path: string;
	chain: LitCompatibleCosmosChain;
	method?: string;
	parameters?: string[];
	returnValueTest: CosmosReturnValueTest;
}
export type SaveEncryptionKeyArgs = {
	unifiedAccessControlConditions: CosmosAccessControlCondition[];
	symmetricKey: CryptoKey;
	authSig: CosmosAuthSignature;
	chain: string;
};
export type GetEncryptionKeyArgs = {
	unifiedAccessControlConditions: CosmosAccessControlCondition[];
	toDecrypt: string;
	authSig: CosmosAuthSignature;
	chain: string;
};
export type EncryptStringMethodResult = EncryptResponse;
export type DecryptToStringMethodResult = DecryptResponse;
export type EncryptStringMethod = (str: string) => Promise<EncryptStringMethodResult>;
export type DecryptToStringMethod = (
	encryptedString: Blob,
	symmetricKey: Uint8Array
) => Promise<DecryptToStringMethodResult>;
export type LitNetwork = (typeof LitNetworksV3)[keyof typeof LitNetworksV3];
export type LitCompatibleCosmosChain = (typeof LitCompatibleCosmosChainsV3)[keyof typeof LitCompatibleCosmosChainsV3];
export type LitProtocolOptions = {
	cosmosAuthWallet: Secp256k1HdWallet;
	litNetwork?: LitNetwork;
	chain?: LitCompatibleCosmosChain;
};
export type TxNonceFormat = (typeof TxNonceFormats)[keyof typeof TxNonceFormats];

export const LitNetworksV3 = {
	cayenne: 'cayenne',
	localhost: 'localhost',
	custom: 'custom',
} as const;
export const LitCompatibleCosmosChainsV3 = {
	cosmos: 'cosmos',
	cheqdMainnet: 'cheqdMainnet',
	cheqdTestnet: 'cheqdTestnet',
} as const;
export const TxNonceFormats = { entropy: 'entropy', uuid: 'uuid', timestamp: 'timestamp' } as const;

export class LitProtocol {
	client: LitNodeClientNodeJs | LitNodeClient;
	litNetwork: LitNetwork = LitNetworksV3.cayenne;
	chain: LitCompatibleCosmosChain = LitCompatibleCosmosChainsV3.cheqdTestnet;
	private readonly cosmosAuthWallet: Secp256k1HdWallet;

	private constructor(options: LitProtocolOptions) {
		// validate options
		if (options.litNetwork && !Object.values(LitNetworksV3).includes(options.litNetwork))
			throw new Error(`[did-provider-cheqd]: lit-protocol: Invalid LitNetwork: ${options.litNetwork}`);
		if (options.chain && !Object.values(LitCompatibleCosmosChainsV3).includes(options.chain))
			throw new Error(`[did-provider-cheqd]: lit-protocol: Invalid LitCompatibleCosmosChain: ${options.chain}`);

		// set options
		if (options.litNetwork) this.litNetwork = options.litNetwork;
		if (options.chain) this.chain = options.chain;
		this.cosmosAuthWallet = options.cosmosAuthWallet;

		// set client as per environment
		this.client = (function (that: LitProtocol) {
			if (isNode) return new LitNodeClientNodeJs({ litNetwork: that.litNetwork, debug: LitProtocolDebugEnabled });
			if (isBrowser) return new LitNodeClient({ litNetwork: that.litNetwork, debug: LitProtocolDebugEnabled });
			throw new Error('[did-provider-cheqd]: lit-protocol: Unsupported runtime environment');
		})(this);
	}

	async connect(): Promise<void> {
		return await this.client.connect();
	}

	async encrypt(
		secret: Uint8Array,
		unifiedAccessControlConditions: NonNullable<UnifiedAccessControlConditions>
	): Promise<ThresholdEncryptionResult> {
		// generate auth signature
		const authSig = await LitProtocol.generateAuthSignature(this.cosmosAuthWallet);

		// encrypt
		const { ciphertext: encryptedString, dataToEncryptHash: stringHash } = (await this.client.encrypt({
			chain: this.chain,
			dataToEncrypt: secret,
			unifiedAccessControlConditions,
			authSig,
		})) satisfies EncryptStringMethodResult;

		return {
			encryptedString: fromString(encryptedString, 'base64'),
			stringHash,
		};
	}

	async decrypt(
		encryptedString: string,
		stringHash: string,
		unifiedAccessControlConditions: NonNullable<UnifiedAccessControlConditions>
	): Promise<string> {
		// generate auth signature
		const authSig = await LitProtocol.generateAuthSignature(this.cosmosAuthWallet);

		// decrypt
		const { decryptedData } = (await this.client.decrypt({
			chain: this.chain,
			ciphertext: encryptedString,
			dataToEncryptHash: stringHash,
			unifiedAccessControlConditions,
			authSig,
		})) satisfies DecryptToStringMethodResult;

		return toString(decryptedData, 'utf-8');
	}

	static async encryptDirect(data: Uint8Array): Promise<SymmetricEncryptionResult> {
		try {
			// generate symmetric key
			const symmetricKey = await generateSymmetricKey();

			// generate iv
			const iv = crypto.getRandomValues(new Uint8Array(12));

			// encrypt
			const encrypted = await crypto.subtle.encrypt(
				{
					name: 'AES-GCM',
					iv,
				},
				symmetricKey,
				data
			);

			// export symmetric key
			const exportedSymmetricKey = await crypto.subtle.exportKey('raw', symmetricKey);

			return {
				encryptedString: new Blob([iv, new Uint8Array(encrypted)]),
				stringHash: toString(new Uint8Array(await crypto.subtle.digest('SHA-256', data)), 'hex'),
				symmetricKey: new Uint8Array(exportedSymmetricKey),
			} satisfies SymmetricEncryptionResult;
		} catch (error) {
			// standardize error
			throw new Error(
				`[did-provider-cheqd]: symmetric-encryption: Encryption failed: ${(error as Error).message || error}`
			);
		}
	}

	static async decryptDirect(encryptedString: Blob, symmetricKey: Uint8Array): Promise<Uint8Array> {
		try {
			// import symmetric key
			const importedSymmetricKey = await crypto.subtle.importKey(
				'raw',
				symmetricKey,
				{
					name: 'AES-GCM',
				},
				true,
				['encrypt', 'decrypt']
			);

			// extract iv and encrypted data
			const [iv, encryptedData] = await Promise.all([
				encryptedString.slice(0, 12).arrayBuffer(),
				encryptedString.slice(12).arrayBuffer(),
			]);

			// decrypt
			const decrypted = await crypto.subtle.decrypt(
				{
					name: 'AES-GCM',
					iv: new Uint8Array(iv),
				},
				importedSymmetricKey,
				encryptedData
			);

			return new Uint8Array(decrypted);
		} catch (error) {
			// standardize error
			throw new Error(
				`[did-provider-cheqd]: symmetric-decryption: Decryption failed: ${(error as Error).message || error}`
			);
		}
	}

	static async create(options: Partial<LitProtocolOptions>): Promise<LitProtocol> {
		// instantiate underlying cosmos auth wallet
		if (!options.cosmosAuthWallet)
			options.cosmosAuthWallet = await Secp256k1HdWallet.generate(24, {
				prefix: await LitProtocol.getCosmosWalletPrefix(options?.chain),
			});

		// validate top-level options chain
		if (!options?.chain) options.chain = LitCompatibleCosmosChainsV3.cheqdTestnet;

		// validate top-level options litNetwork
		if (!options?.litNetwork) options.litNetwork = LitNetworksV3.cayenne;

		const litProtocol = new LitProtocol(options as LitProtocolOptions);
		await litProtocol.connect();
		return litProtocol;
	}

	static async getCosmosWalletPrefix(chain?: LitCompatibleCosmosChain): Promise<string> {
		switch (chain) {
			case LitCompatibleCosmosChainsV3.cosmos:
				return 'cosmos';
			case LitCompatibleCosmosChainsV3.cheqdMainnet:
				return 'cheqd';
			case LitCompatibleCosmosChainsV3.cheqdTestnet:
				return 'cheqd';
			default:
				return 'cheqd';
		}
	}

	static async generateAuthSignature(wallet: OfflineAminoSigner): Promise<AuthSignature> {
		const signerAddress = (await wallet.getAccounts())[0].address;
		const signData = await LitProtocol.generateSignData();
		const signDoc = await LitProtocol.generateSignDoc(signerAddress, signData);
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

	static async generateTxNonce(format?: TxNonceFormat, entropyLength?: number): Promise<string> {
		switch (format) {
			case TxNonceFormats.entropy:
				return toString(await randomBytes(entropyLength || 64), 'hex');
			case TxNonceFormats.uuid:
				return v4();
			case TxNonceFormats.timestamp:
				return new Date().toISOString();
			default:
				return v4();
		}
	}

	static async generateCosmosAccessControlConditionBalance(
		returnValueTest: CosmosReturnValueTest,
		chain: LitCompatibleCosmosChain = LitCompatibleCosmosChainsV3.cheqdTestnet,
		address = ':userAddress'
	): Promise<CosmosAccessControlCondition> {
		return {
			conditionType: 'cosmos',
			path: `/cosmos/bank/v1beta1/balances/${address}`,
			chain,
			returnValueTest,
		};
	}

	static async generateCosmosAccessControlConditionTransactionMemo(
		returnValueTest: CosmosReturnValueTest,
		amount: string,
		sender: string,
		recipient = ':userAddress',
		chain: LitCompatibleCosmosChain = LitCompatibleCosmosChainsV3.cheqdTestnet
	): Promise<CosmosAccessControlCondition> {
		return {
			conditionType: 'cosmos',
			path: `/cosmos/tx/v1beta1/txs?events=transfer.recipient='${recipient}'&events=transfer.sender='${sender}'&events=transfer.amount='${amount}'&order_by=2`,
			chain,
			returnValueTest,
		};
	}

	static async generateCosmosAccessControlConditionInverseTimelock(
		returnValueTest: CosmosReturnValueTest,
		amount: string,
		recipient = ':userAddress',
		blockHeight = 'latest',
		chain: LitCompatibleCosmosChain = LitCompatibleCosmosChainsV3.cheqdTestnet
	): Promise<CosmosAccessControlCondition> {
		return {
			conditionType: 'cosmos',
			path: `/cosmos/tx/v1beta1/txs?events=transfer.recipient='${recipient}'&events=transfer.amount='${amount}'&order_by=2&pagination.limit=1`,
			chain,
			method: 'timelock',
			parameters: [blockHeight],
			returnValueTest,
		};
	}
}
