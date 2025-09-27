import { RandomBytes } from '@/curves/types';
import { SignatureCurve } from '../types';
import { createSignatureCurve } from './createSignatureCurve';

/**
 * A RandomBytes function that throws an error when called.
 * Used to prevent RNG usage in signature curves where it's disallowed.
 *
 * @param {number} [_byteLength] - The byte length to generate (unused)
 * @returns {Uint8Array} Never returns - always throws an error
 * @throws {Error} Always throws an error indicating RNG usage is disallowed
 */
const throwingRandomBytes: RandomBytes = (_byteLength?: number): Uint8Array => {
  throw new Error('RNG usage is disallowed for this curve');
};

/**
 * Creates a signature curve instance with RNG operations disabled.
 * This function creates a signature curve where random number generation
 * operations (randomBytes, randomPrivateKey) are not available.
 *
 * @param {string} curveName - The name of the curve to use for the signature. Supported values: 'P-256', 'P-384', 'P-521', 'secp256k1', 'Ed25519'.
 * @returns {Omit<SignatureCurve, 'randomBytes' | 'randomPrivateKey'>} A signature curve instance with RNG operations omitted.
 * @throws {Error} Throws an error if the curve name is unsupported.
 */
export const createSignatureCurveRngDisallowed = (
  curveName: string,
): Omit<SignatureCurve, 'randomBytes' | 'randomPrivateKey'> => {
  const curve = createSignatureCurve(curveName, throwingRandomBytes);

  return curve;
};
