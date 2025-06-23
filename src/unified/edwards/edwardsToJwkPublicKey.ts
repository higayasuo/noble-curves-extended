import { CurveFn } from '@noble/curves/abstract/edwards';
import type { JwkPublicKey } from '@/unified/types';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts an edwards public key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the public key conversion fails.
 */
export const edwardsToJwkPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    const keyByteLength = curve.CURVE.nByteLength;
    if (publicKey.length !== keyByteLength) {
      throw new Error('Invalid public key length');
    }

    return {
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      x: encodeBase64Url(publicKey),
    };
  } catch (error) {
    console.error(error);
    throw new Error('Failed to convert public key to JWK');
  }
};
