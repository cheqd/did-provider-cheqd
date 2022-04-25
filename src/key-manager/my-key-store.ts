import { IKey, ManagedKeyInfo } from '@veramo/core'
import { AbstractKeyStore, AbstractPrivateKeyStore, ManagedPrivateKey } from '@veramo/key-manager'
import { ImportablePrivateKey } from '@veramo/key-manager/build/abstract-private-key-store'

/**
 * This type of class would allow you to define your own storage for the key mappings that a Veramo agent manages.
 * `@veramo/key-manager` can be configured with a class like this to customize the way it stores key metadata.
 *
 * If you don't want to customize this, then it is safe to remove from the template.
 *
 * @alpha
 */
export class MyKeyStore extends AbstractKeyStore {
  async list(args: {}): Promise<ManagedKeyInfo[]> {
    throw new Error('KeyStore list not implemented.')
  }

  async get({ kid }: { kid: string }): Promise<IKey> {
    throw Error('KeyStore get not implemented')
  }

  async delete({ kid }: { kid: string }) {
    throw Error('KeyStore delete not implemented')
    return true
  }

  async import(args: IKey) {
    throw Error('KeyStore import not implemented')
    return true
  }
}

/**
 * This type of class would allow you to define **your own storage for the key material** that the default Veramo AbstractKeyManagementSystem implementation uses.
 * `@veramo/kms-local` can be configured with a class like this to customize the way it stores key material.
 *
 * If you don't want to customize this, then it is safe to remove from the template.
 *
 * @alpha
 */
 export class MyPrivateKeyStore extends AbstractPrivateKeyStore {
   import(args: ImportablePrivateKey): Promise<ManagedPrivateKey> {
     throw new Error('Method not implemented.')
   }
   get(args: { alias: string }): Promise<ManagedPrivateKey> {
     throw new Error('Method not implemented.')
   }
   delete(args: { alias: string }): Promise<boolean> {
     throw new Error('Method not implemented.')
   }
   list(args: {}): Promise<ManagedPrivateKey[]> {
     throw new Error('Method not implemented.')
   }

}
