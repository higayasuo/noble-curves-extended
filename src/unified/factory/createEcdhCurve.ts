import { RandomBytes } from '@/curves/types';
import { EcdhCurve, EcdhCurveName } from '../types';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { Weierstrass } from '@/unified/weierstrass/Weierstrass';
import { createX25519 } from '@/curves/montgomery/x25519';
import { Montgomery } from '@/unified/montgomery/Montgomery';

/**
 * Creates an ECDH curve instance based on the specified curve name.
 *
 * @param {EcdhCurveName} curveName - The name of the curve to use for ECDH.
 * @param {RandomBytes} randomBytes - A function to generate random bytes.
 * @returns {EcdhCurve} An ECDH curve instance for the specified curve.
 * @throws {Error} Throws an error if the curve name is unsupported.
 */
export const createEcdhCurve = (
  curveName: EcdhCurveName,
  randomBytes: RandomBytes,
): EcdhCurve => {
  switch (curveName) {
    case 'P-256':
      return new Weierstrass(createP256(randomBytes), randomBytes);
    case 'P-384':
      return new Weierstrass(createP384(randomBytes), randomBytes);
    case 'P-521':
      return new Weierstrass(createP521(randomBytes), randomBytes);
    case 'secp256k1':
      return new Weierstrass(createSecp256k1(randomBytes), randomBytes);
    case 'X25519':
      return new Montgomery(createX25519(randomBytes), randomBytes);
    default:
      throw new Error(`Unsupported signature curve: ${curveName}`);
  }
};
