import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPrivateKey } from '@/unified/types';
import { compareUint8Arrays, decodeBase64Url } from 'u8a-utils';
import { edwardsToRawPublicKeyInternal } from './edwardsToRawPublicKey';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted edwards private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - The expected byte length of the key.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const edwardsToRawPrivateKey = (
  curve: CurveFn,
  keyByteLength: number,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  try {
    return edwardsToRawPrivateKeyInternal(curve, keyByteLength, jwkPrivateKey);
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw private key');
  }
};

/**
 * Internal function to convert a JWK formatted edwards private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - The expected byte length of the key.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 * @internal
 */
export const edwardsToRawPrivateKeyInternal = (
  curve: CurveFn,
  keyByteLength: number,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  const publicKey = edwardsToRawPublicKeyInternal(
    curve,
    keyByteLength,
    jwkPrivateKey,
  );

  if (jwkPrivateKey.d == null) {
    throw new Error('Missing required parameter for d');
  }

  if (typeof jwkPrivateKey.d !== 'string') {
    throw new Error('Invalid parameter type for d');
  }

  let decodedD!: Uint8Array;
  try {
    decodedD = decodeBase64Url(jwkPrivateKey.d);
  } catch (e) {
    throw new Error('Malformed encoding for d');
  }

  if (decodedD.length !== keyByteLength) {
    throw new Error(
      `Invalid the length of the key data for d: ${decodedD.length}, expected ${keyByteLength}`,
    );
  }

  if (!compareUint8Arrays(curve.getPublicKey(decodedD), publicKey)) {
    throw new Error(
      'The public key derived from the private key does not match the public key in the JWK',
    );
  }

  return decodedD;
};
