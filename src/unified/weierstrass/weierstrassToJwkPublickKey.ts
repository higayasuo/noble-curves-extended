import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { getWeierstrassCurveName } from '@/curves/weierstrass';
import { JwkPublicKey } from '../types';
import { encodeBase64Url } from 'u8a-utils';
import { getWeierstrassSignatureAlgorithm } from '@/curves/weierstrass/getWeierstrassSignatureAlgorithm';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a Weierstrass public key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the public key conversion fails.
 */
export const weierstrassToJwkPublickKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    const point = curve.ProjectivePoint.fromHex(publicKey);
    const uncompressed = point.toRawBytes(false);
    const keyLength = (uncompressed.length - 1) / 2;
    const x = uncompressed.slice(1, 1 + keyLength);
    const y = uncompressed.slice(1 + keyLength);

    return {
      kty: 'EC',
      crv: getWeierstrassCurveName(curve),
      alg: getWeierstrassSignatureAlgorithm(curve),
      x: encodeBase64Url(x),
      y: encodeBase64Url(y),
    };
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert public key to JWK');
  }
};
