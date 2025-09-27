import { CurveFn } from '@noble/curves/abstract/montgomery';
import type { CurveName, JwkPublicKey } from '../types';
import { encodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a raw Montgomery public key to JWK format.
 *
 * @param {CurveFn} _curve - The curve function (unused in this implementation).
 * @param {number} keyByteLength - The expected byte length of the public key.
 * @param {CurveName} curveName - The curve name for the JWK.
 * @param {Uint8Array} publicKey - The public key in raw format.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the conversion fails.
 */
export const montgomeryToJwkPublicKey = (
  _curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    if (publicKey.length !== keyByteLength) {
      throw new Error(
        `Invalid public key length: ${publicKey.length}, expected ${keyByteLength}`,
      );
    }

    return {
      kty: 'OKP',
      crv: curveName,
      x: encodeBase64Url(publicKey),
    };
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert public key to JWK');
  }
};
