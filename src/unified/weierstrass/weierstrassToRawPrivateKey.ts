import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { JwkPrivateKey } from '@/unified/types';
import { compareUint8Arrays, decodeBase64Url } from 'u8a-utils';
import { weierstrassToRawPublicKeyInternal } from './weierstrassToRawPublicKey';

/**
 * Converts a JWK formatted Weierstrass private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const weierstrassToRawPrivateKey = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  try {
    return weierstrassToRawPrivateKeyInternal(curve, jwkPrivateKey);
  } catch (e) {
    console.error(e);
    throw new Error('Failed to convert JWK to raw private key');
  }
};

/**
 * Internal function to convert a JWK formatted Weierstrass private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const weierstrassToRawPrivateKeyInternal = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  const publicKey = weierstrassToRawPublicKeyInternal(curve, jwkPrivateKey);

  if (jwkPrivateKey.d === undefined || jwkPrivateKey.d === null) {
    throw new Error('Invalid JWK: missing required parameter for d');
  }

  if (typeof jwkPrivateKey.d !== 'string') {
    throw new Error('Invalid JWK: invalid parameter type for d');
  }

  let decodedD!: Uint8Array;
  try {
    decodedD = decodeBase64Url(jwkPrivateKey.d);
  } catch (e) {
    throw new Error('Invalid JWK: malformed encoding for d');
  }

  if (decodedD.length !== curve.CURVE.nByteLength) {
    throw new Error('Invalid JWK: invalid key data for d');
  }

  if (!compareUint8Arrays(curve.getPublicKey(decodedD, false), publicKey)) {
    throw new Error('Invalid JWK: invalid key data for d');
  }

  return decodedD;
};
