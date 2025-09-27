import { RandomBytes } from '@/curves/types';
import { SignatureCurve } from '../types';
import { Ed25519 } from '../edwards/Ed25519';
import { P384 } from '../weierstrass/P384';
import { P521 } from '../weierstrass/P521';
import { Secp256k1 } from '../weierstrass/Secp256k1';
import { P256 } from '../weierstrass/P256';

/**
 * Creates a signature curve instance based on the specified curve name.
 *
 * @param {string} curveName - The name of the curve to use for the signature. Supported values: 'P-256', 'P-384', 'P-521', 'secp256k1', 'Ed25519'.
 * @param {RandomBytes} randomBytes - A function to generate random bytes.
 * @returns {SignatureCurve} A signature curve instance for the specified curve.
 * @throws {Error} Throws an error if the curve name is unsupported.
 */
export const createSignatureCurve = (
  curveName: string,
  randomBytes: RandomBytes,
): SignatureCurve => {
  switch (curveName) {
    case 'P-256':
      return new P256(randomBytes);
    case 'P-384':
      return new P384(randomBytes);
    case 'P-521':
      return new P521(randomBytes);
    case 'secp256k1':
      return new Secp256k1(randomBytes);
    case 'Ed25519':
      return new Ed25519(randomBytes);
    default:
      throw new Error(`Unsupported signature curve: ${curveName}`);
  }
};
