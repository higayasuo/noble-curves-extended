import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPrivateKey } from '../types';
import { compareUint8Arrays, decodeBase64Url } from 'u8a-utils';
import { montgomeryToRawPublicKeyInternal } from './montgomeryToRawPublicKey';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK (JSON Web Key) to a raw Montgomery private key.
 *
 * @param {CurveFn} curve - The curve function used to validate the keys.
 * @param {JwkPrivateKey} jwkPrivateKey - The JWK to convert.
 * @returns {Uint8Array} The raw private key as a Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or the private key is invalid.
 */
export const montgomeryToRawPrivateKey = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  try {
    return montgomeryToRawPrivateKeyInternal(curve, jwkPrivateKey);
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw private key');
  }
};

/**
 * Internal function to convert a JWK formatted Montgomery private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 * @internal
 */
export const montgomeryToRawPrivateKeyInternal = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  const publicKey = montgomeryToRawPublicKeyInternal(curve, jwkPrivateKey);

  if (jwkPrivateKey.d === undefined || jwkPrivateKey.d === null) {
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

  if (decodedD.length !== curve.GuBytes.length) {
    throw new Error(
      `Invalid the length of the key data for d: ${decodedD.length}, expected ${curve.GuBytes.length}`,
    );
  }

  if (!compareUint8Arrays(curve.getPublicKey(decodedD), publicKey)) {
    throw new Error(
      'The public key derived from the private key does not match the public key in the JWK',
    );
  }

  return decodedD;
};
