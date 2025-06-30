import { CurveFn } from '@noble/curves/abstract/montgomery';
import type { JwkPublicKey } from '../types';
import { encodeBase64Url } from 'u8a-utils';
import { getMontgomeryCurveName } from '@/curves/montgomery';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a raw Montgomery public key to JWK format.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {Uint8Array} publicKey - The public key in raw format.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the conversion fails.
 */
export const montgomeryToJwkPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    if (publicKey.length !== curve.GuBytes.length) {
      throw new Error('Invalid public key length');
    }

    return {
      kty: 'OKP',
      crv: getMontgomeryCurveName(curve),
      x: encodeBase64Url(publicKey),
    };
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert public key to JWK');
  }
};
