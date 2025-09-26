import { CurveFn } from '@noble/curves/abstract/edwards';
import type { JwkPublicKey } from '@/unified/types';
import { encodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts an edwards public key to a JWK format.
 *
 * @param {CurveFn} _curve - The curve function (unused in current implementation).
 * @param {number} keyByteLength - The expected byte length of the public key.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the public key conversion fails.
 */
export const edwardsToJwkPublicKey = (
  _curve: CurveFn,
  keyByteLength: number,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    if (publicKey.byteLength !== keyByteLength) {
      throw new Error(
        `Invalid public key byte length: ${publicKey.byteLength}, expected ${keyByteLength}`,
      );
    }

    return {
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      x: encodeBase64Url(publicKey),
    };
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert public key to JWK');
  }
};
