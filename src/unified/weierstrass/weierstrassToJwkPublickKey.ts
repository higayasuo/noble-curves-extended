import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { CurveName, JwkPublicKey, SignatureAlgorithmName } from '../types';
import { encodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a Weierstrass public key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key.
 * @param {number} keyByteLength - The expected byte length of each coordinate (x, y).
 * @param {CurveName} curveName - The name of the curve to validate against.
 * @param {SignatureAlgorithmName} signatureAlgorithmName - The signature algorithm name for the JWK.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the public key conversion fails.
 */
export const weierstrassToJwkPublickKey = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  signatureAlgorithmName: SignatureAlgorithmName,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    const point = curve.ProjectivePoint.fromHex(publicKey);
    const uncompressed = point.toRawBytes(false);

    if (uncompressed.length !== keyByteLength * 2 + 1) {
      throw new Error(
        `Invalid uncompressed public key length: ${
          uncompressed.length
        }, expected ${keyByteLength * 2 + 1}`,
      );
    }

    const x = uncompressed.slice(1, 1 + keyByteLength);
    const y = uncompressed.slice(1 + keyByteLength);

    return {
      kty: 'EC',
      crv: curveName,
      alg: signatureAlgorithmName,
      x: encodeBase64Url(x),
      y: encodeBase64Url(y),
    };
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert public key to JWK');
  }
};
