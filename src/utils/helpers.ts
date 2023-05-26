import { generate as generateSecret, type GenerateOptions } from 'generate-password'
import { toString } from 'uint8arrays/to-string'

export async function randomFromRange(min: number, max: number, notIn: number[]): Promise<number> {
    const random = Math.floor(Math.random() * (max - min + 1) + min)
    if (notIn.includes(random)) {
        return await randomFromRange(min, max, notIn)
    }
    return random
}

export async function randomUniqueSubsetInRange(min: number, max: number, count: number): Promise<Array<number>> {
    const subset: number[] = []
    for (let i = 0; i < count; i++) {
        subset.push(await randomFromRange(min, max, subset))
    }
    return subset
}

export async function randomBytes(length: number): Promise<Buffer> {
    return Buffer.from(
        Array.from(
            { length },
            () => Math.floor(Math.random() * 256),
        ),
    )
}

export async function randomUniqueSecret(options?: GenerateOptions): Promise<string> {
    return generateSecret({
        length: 64,
        numbers: true,
        symbols: true,
        uppercase: true,
        ...options,
    })
}

export async function initialiseIndexArray(length: number): Promise<Array<boolean>> {
    return Array(length).fill(true)
}

export async function shuffleArray<T>(array: Array<T>): Promise<Array<T>> {
    const shuffled = array.sort(() => Math.random() - 0.5)
    return shuffled
}

export async function toBlob(data: Uint8Array): Promise<Blob> {
    return new Blob([data])
}

export async function blobToHexString(blob: Blob): Promise<string> {
    // buffer from blob
    const buffer = await blob.arrayBuffer()

    // convert buffer to uint8Array
    const uint8Array = new Uint8Array(buffer)

    return toString(uint8Array, 'hex')
}

export function unescapeUnicode(str: string): string {
    return str.replace(/\\u([a-fA-F0-9]{4})/g, (m, cc) => {
        return String.fromCharCode(parseInt(cc, 16))
    })
}