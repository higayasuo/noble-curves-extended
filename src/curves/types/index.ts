/**
 * Function type that generates random bytes.
 * @param bytesLength - Optional number of bytes to generate. If not provided, implementation should choose appropriate length.
 * @returns Uint8Array containing the generated random bytes.
 */
export type RandomBytes = (bytesLength?: number) => Uint8Array;
