import {
    OfflineAminoSigner,
    Secp256k1HdWallet,
    StdSignDoc
} from '@cosmjs/amino'
import { toString } from 'uint8arrays/to-string'
import { sha256 } from '@cosmjs/crypto'
import {
    LitNodeClientNodeJs,
    LitNodeClient,
    decryptString,
    encryptString,
} from '@lit-protocol/lit-node-client'
import { JsonSaveEncryptionKeyRequest } from '@lit-protocol/types'
import { randomBytes } from '../utils/helpers.js'
import { isBrowser, isNode } from '../utils/env.js'
import { v4 } from 'uuid'

export type EncryptionResult = {
    encryptedString: Blob
    encryptedSymmetricKey: string
    symmetricKey?: Uint8Array
}
export type AuthSignature = {
    sig: string
    derivedVia: 'cosmos.signArbitrary',
    signedMessage: string
    address: string
}
export type CosmosAuthSignature = {
    cosmos: AuthSignature
}
export type CosmosReturnValueTest = {
    key: string
    comparator: string
    value: string
}
export type CosmosAccessControlCondition = {
    conditionType: 'cosmos'
    path: string
    chain: string
    returnValueTest: CosmosReturnValueTest
}
export type SaveEncryptionKeyArgs = {
    unifiedAccessControlConditions: CosmosAccessControlCondition[]
    symmetricKey: CryptoKey
    authSig: CosmosAuthSignature
    chain: string
}
export type GetEncryptionKeyArgs = {
    unifiedAccessControlConditions: CosmosAccessControlCondition[]
    toDecrypt: string
    authSig: CosmosAuthSignature
    chain: string
}
export type EncryptStringMethodResult = { encryptedString: Blob, symmetricKey: Uint8Array }
export type DecryptStringMethodResult = string
export type EncryptStringMethod = (str: string) => Promise<EncryptStringMethodResult>
export type DecryptStringMethod = (encryptedString: Blob, symmetricKey: Uint8Array) => Promise<DecryptStringMethodResult>
export type LitNetwork = typeof LitNetworks[keyof typeof LitNetworks]
export type LitCompatibleCosmosChain = typeof LitCompatibleCosmosChains[keyof typeof LitCompatibleCosmosChains]
export type LitProtocolOptions = { cosmosAuthWallet: Secp256k1HdWallet, litNetwork?: LitNetwork, chain?: LitCompatibleCosmosChain }
export type TxNonceFormat = typeof TxNonceFormats[keyof typeof TxNonceFormats]

export const LitNetworks = { jalapeno: 'jalapeno', serrano: 'serrano', localhost: 'localhost', custom: 'custom' } as const
export const LitCompatibleCosmosChains = { cosmos: 'cosmos', cheqdMainnet: 'cheqdMainnet', cheqdTestnet: 'cheqdTestnet' } as const
export const TxNonceFormats = { entropy: 'entropy', uuid: 'uuid', timestamp: 'timestamp' } as const

export class LitProtocol {
    client: LitNodeClientNodeJs | LitNodeClient
    litNetwork: LitNetwork = LitNetworks.serrano
    chain: LitCompatibleCosmosChain = LitCompatibleCosmosChains.cheqdTestnet
    private readonly cosmosAuthWallet: Secp256k1HdWallet

    private constructor(options: LitProtocolOptions) {
        // validate options
        if (options.litNetwork && !Object.values(LitNetworks).includes(options.litNetwork)) throw new Error(`[did-provider-cheqd]: lit-protocol: Invalid LitNetwork: ${options.litNetwork}`)
        if (options.chain && !Object.values(LitCompatibleCosmosChains).includes(options.chain)) throw new Error(`[did-provider-cheqd]: lit-protocol: Invalid LitCompatibleCosmosChain: ${options.chain}`)

        // set options
        if (options.litNetwork) this.litNetwork = options.litNetwork
        if (options.chain) this.chain = options.chain
        this.cosmosAuthWallet = options.cosmosAuthWallet

        // set client as per environment
        this.client = function(that: LitProtocol) {
            if (isNode) return new LitNodeClientNodeJs({ litNetwork: that.litNetwork })
            if (isBrowser) return new LitNodeClient({ litNetwork: that.litNetwork })
            throw new Error('[did-provider-cheqd]: lit-protocol: Unsupported runtime environment')
        }(this)
    }

    async connect(): Promise<void> {
        return await this.client.connect()
    }

    async encrypt(secret: string, unifiedAccessControlConditions: NonNullable<JsonSaveEncryptionKeyRequest['unifiedAccessControlConditions']>, returnSymmetricKey = false): Promise<EncryptionResult> {
        const authSig = await LitProtocol.generateAuthSignature(this.cosmosAuthWallet)
        const { encryptedString, symmetricKey } = await encryptString(secret as string) as EncryptStringMethodResult
        const encryptedSymmetricKey = await this.client.saveEncryptionKey(
            {
                unifiedAccessControlConditions,
                symmetricKey,
                authSig: authSig,
                chain: this.chain
            }
        )

        return {
            encryptedString,
            encryptedSymmetricKey: toString(encryptedSymmetricKey, 'hex'),
            symmetricKey: returnSymmetricKey ? symmetricKey : undefined
        }
    }

    async decrypt(encryptedString: Blob, encryptedSymmetricKey: string, unifiedAccessControlConditions: NonNullable<JsonSaveEncryptionKeyRequest['unifiedAccessControlConditions']>): Promise<string> {
        const authSig = await LitProtocol.generateAuthSignature(this.cosmosAuthWallet)
        const symmetricKey = await this.client.getEncryptionKey(
            {
                unifiedAccessControlConditions,
                toDecrypt: encryptedSymmetricKey,
                authSig: authSig,
                chain: this.chain
            }
        )
        return await decryptString(encryptedString, symmetricKey) as DecryptStringMethodResult
    }

    static async encryptDirect(secret: string): Promise<EncryptStringMethodResult> {
        const { encryptedString, symmetricKey } = await encryptString(secret as string) as EncryptStringMethodResult
        return {
            encryptedString,
            symmetricKey
        }
    }

    static async decryptDirect(encryptedString: Blob, symmetricKey: Uint8Array): Promise<DecryptStringMethodResult> {
        return await decryptString(encryptedString, symmetricKey) as DecryptStringMethodResult
    }

    static async create(options: Partial<LitProtocolOptions>): Promise<LitProtocol> {
        // instantiate underlying cosmos auth wallet
        if (!options.cosmosAuthWallet) options.cosmosAuthWallet = await Secp256k1HdWallet.generate(24, { prefix: await LitProtocol.getCosmosWalletPrefix(options?.chain) })

        // validate top-level options chain
        if (!options?.chain) options.chain = LitCompatibleCosmosChains.cheqdTestnet

        // validate top-level options litNetwork
        if (!options?.litNetwork) options.litNetwork = LitNetworks.serrano

        const litProtocol = new LitProtocol(options as LitProtocolOptions)
        await litProtocol.connect()
        return litProtocol
    }

    static async getCosmosWalletPrefix(chain?: LitCompatibleCosmosChain): Promise<string> {
        switch (chain) {
            case LitCompatibleCosmosChains.cosmos:
                return 'cosmos'
            case LitCompatibleCosmosChains.cheqdMainnet:
                return 'cheqd'
            case LitCompatibleCosmosChains.cheqdTestnet:
                return 'cheqd'
            default:
                return 'cheqd'
        }
    }

    static async generateAuthSignature(wallet: OfflineAminoSigner): Promise<AuthSignature> {
        const signerAddress = (await wallet.getAccounts())[0].address
        const signData = await LitProtocol.generateSignData()
        const signDoc = await LitProtocol.generateSignDoc(signerAddress, signData)
        const result = await wallet.signAmino(signerAddress, signDoc)
        return {
            address: signerAddress,
            derivedVia: 'cosmos.signArbitrary',
            sig: result.signature.signature,
            signedMessage: toString(sha256(new TextEncoder().encode(JSON.stringify(signDoc))), 'hex'), // <-- hex encoded sha256 hash of the json stringified signDoc
        }
    }

    static async generateSignDoc(address: string, data: Uint8Array): Promise<StdSignDoc> {
        return {
            account_number: '0',
            chain_id: '',
            fee: {
                amount: [],
                gas: '0'
            },
            memo: '',
            msgs: [
                {
                    type: 'sign/MsgSignData',
                    value: {
                        data: toString(data, 'base64'),
                        signer: address,
                    }
                }
            ],
            sequence: '0',
        } // <-- should be sorted alphabetically
    }

    static async generateSignData(): Promise<Uint8Array> {
        return new TextEncoder().encode(`I am creating an account to use Lit Protocol at 2023-02-21T16:40:15.305Z`) // <-- lit nodes search for this string in the signData
    }

    static async generateTxNonce(format?: TxNonceFormat, entropyLength?: number): Promise<string> {
        switch (format) {
            case TxNonceFormats.entropy:
                return toString(await randomBytes(entropyLength || 64), 'hex')
            case TxNonceFormats.uuid:
                return v4()
            case TxNonceFormats.timestamp:
                return new Date().toISOString()
            default:
                return v4()
        }
    }

    static async generateCosmosAccessControlConditionBalance(returnValueTest: CosmosReturnValueTest, chain: LitCompatibleCosmosChain = LitCompatibleCosmosChains.cheqdTestnet, address = ':userAddress'): Promise<CosmosAccessControlCondition> {
        return {
            conditionType: 'cosmos',
            path: `/cosmos/bank/v1beta1/balances/${address}`,
            chain,
            returnValueTest
        }
    }

    static async generateCosmosAccessControlConditionTransactionMemo(returnValueTest: CosmosReturnValueTest, amount: string, sender: string, recipient = ':userAddress', chain: LitCompatibleCosmosChain = LitCompatibleCosmosChains.cheqdTestnet): Promise<CosmosAccessControlCondition> {
        return {
            conditionType: 'cosmos',
            path: `/cosmos/tx/v1beta1/txs?events=transfer.recipient='${recipient}'&events=transfer.sender='${sender}'&events=transfer.amount='${amount}'&order_by=2`,
            chain,
            returnValueTest
        }
    }
}