/**
 * Function type that generates random bytes.
 * @param bytesLength - Optional number of bytes to generate. If not provided, implementation should choose appropriate length.
 * @returns Uint8Array containing the generated random bytes.
 */
export type RandomBytes = (bytesLength?: number) => Uint8Array;

/**
 * Type representing supported NIST curve names.
 * Possible values: 'P-256', 'P-384', 'P-521'
 */
export type NistCurveName = 'P-256' | 'P-384' | 'P-521';

export type Jwk = {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d?: string;
};
