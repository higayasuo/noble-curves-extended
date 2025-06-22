import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { JwkPrivateKey } from '@/unified/types';
import { weierstrassToJwkPublickKey } from './weierstrassToJwkPublickKey';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts an Weierstrass private key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @returns {JwkPrivateKey} The private key in JWK format.
 * @throws {Error} Throws an error if the private key conversion fails.
 */
export const weierstrassToJwkPrivateKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
): JwkPrivateKey => {
  try {
    const publicKey = curve.getPublicKey(privateKey);
    const jwkPublicKey = weierstrassToJwkPublickKey(curve, publicKey);

    return {
      ...jwkPublicKey,
      d: encodeBase64Url(privateKey),
    };
  } catch (error) {
    console.error(error);
    throw new Error('Failed to convert private key to JWK');
  }
};
