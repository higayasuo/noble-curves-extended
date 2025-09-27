/**
 * Function type that generates random bytes.
 * @param byteLength - Optional number of bytes to generate. If not provided, implementation should choose appropriate length.
 * @returns Uint8Array containing the generated random bytes.
 */
export type RandomBytes = (byteLength?: number) => Uint8Array;
