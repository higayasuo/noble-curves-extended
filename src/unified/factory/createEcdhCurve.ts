import { RandomBytes } from '@/curves/types';
import { EcdhCurve } from '../types';
import { createX25519 } from '@/curves/montgomery/x25519';
import { Montgomery } from '@/unified/montgomery/Montgomery';
import { P256 } from '../weierstrass/P256';
import { P521 } from '../weierstrass/P521';
import { P384 } from '../weierstrass/P384';
import { Secp256k1 } from '../weierstrass/Secp256k1';

/**
 * Creates an ECDH curve instance based on the specified curve name.
 *
 * @param {string} curveName - The name of the curve to use for ECDH. Supported values: 'P-256', 'P-384', 'P-521', 'secp256k1', 'X25519'.
 * @param {RandomBytes} randomBytes - A function to generate random bytes.
 * @returns {EcdhCurve} An ECDH curve instance for the specified curve.
 * @throws {Error} Throws an error if the curve name is unsupported.
 */
export const createEcdhCurve = (
  curveName: string,
  randomBytes: RandomBytes,
): EcdhCurve => {
  switch (curveName) {
    case 'P-256':
      return new P256(randomBytes);
    case 'P-384':
      return new P384(randomBytes);
    case 'P-521':
      return new P521(randomBytes);
    case 'secp256k1':
      return new Secp256k1(randomBytes);
    case 'X25519':
      return new Montgomery(createX25519(randomBytes), randomBytes);
    default:
      throw new Error(`Unsupported signature curve: ${curveName}`);
  }
};
