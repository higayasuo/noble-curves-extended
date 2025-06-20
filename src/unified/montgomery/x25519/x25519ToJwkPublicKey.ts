import { CurveFn } from '@noble/curves/abstract/montgomery';
import type { JwkPublicKey } from '../../types';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts a raw X25519 public key to JWK format.
 *
 * @param {CurveFn} _curve - The curve function used for conversion (unused).
 * @param {Uint8Array} publicKey - The public key in raw format.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the conversion fails.
 */
export const x25519ToJwkPublicKey = (
  _curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    if (publicKey.length !== 32) {
      throw new Error('Invalid public key length');
    }

    return {
      kty: 'OKP',
      crv: 'X25519',
      x: encodeBase64Url(publicKey),
      alg: 'ECDH-ES',
    };
  } catch (error) {
    console.error(error);
    throw new Error('Failed to convert public key to JWK');
  }
};
