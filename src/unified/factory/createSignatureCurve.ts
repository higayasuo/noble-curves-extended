import { RandomBytes } from '@/curves/types';
import { SignatureCurve } from '../types';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { Edwards } from '@/unified/edwards/Edwards';
import { Weierstrass } from '@/unified/weierstrass/Weierstrass';

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
      return new Weierstrass(createP256(randomBytes), randomBytes);
    case 'P-384':
      return new Weierstrass(createP384(randomBytes), randomBytes);
    case 'P-521':
      return new Weierstrass(createP521(randomBytes), randomBytes);
    case 'secp256k1':
      return new Weierstrass(createSecp256k1(randomBytes), randomBytes);
    case 'Ed25519':
      return new Edwards(createEd25519(randomBytes), randomBytes);
    default:
      throw new Error(`Unsupported signature curve: ${curveName}`);
  }
};
