import { CurveFn } from '@noble/curves/abstract/montgomery';
import { CurveName, JwkPrivateKey } from '../types';
import { montgomeryToJwkPublicKey } from './montgomeryToJwkPublicKey';
import { encodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a raw Montgomery private key to JWK format.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - The expected byte length of the public key.
 * @param {CurveName} curveName - The curve name for the JWK.
 * @param {Uint8Array} privateKey - The private key in raw format.
 * @returns {JwkPrivateKey} The private key in JWK format.
 * @throws {Error} Throws an error if the conversion fails.
 */
export const montgomeryToJwkPrivateKey = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  privateKey: Uint8Array,
): JwkPrivateKey => {
  try {
    const publicKey = curve.getPublicKey(privateKey);
    const jwkPublicKey = montgomeryToJwkPublicKey(
      curve,
      keyByteLength,
      curveName,
      publicKey,
    );
    const jwkPrivateKey: JwkPrivateKey = {
      ...jwkPublicKey,
      d: encodeBase64Url(privateKey),
    };

    return jwkPrivateKey;
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert private key to JWK');
  }
};
