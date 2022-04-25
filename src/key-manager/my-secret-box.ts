import { AbstractSecretBox } from '@veramo/key-manager'

/**
 * This type of class would allow you to define your own encryption for the key material that a Veramo agent manages.
 * `@veramo/key-manager#PrivateKeyStore` and  can be configured with a class like this to customize the way it stores key material.
 *
 * If you don't want to customize this, then it is safe to remove from the template.
 *
 * @alpha
 */
export class SecretBox extends AbstractSecretBox {
  constructor(private secretKey: string) {
    super()
    if (!secretKey) {
      throw Error('Secret key is required')
    }
  }

  async encrypt(message: string): Promise<string> {
    throw Error('SecretBox encrypt not implemented')
  }

  async decrypt(encryptedMessageHex: string): Promise<string> {
    throw Error('SecretBox decrypt not implemented')
  }
}
