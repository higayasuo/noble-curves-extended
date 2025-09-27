import { CurveFn } from '@noble/curves/abstract/montgomery';
import { CurveName, JwkPublicKey } from '../types';
import { decodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted Montgomery public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - The expected byte length of the key.
 * @param {CurveName} curveName - The name of the curve to validate against.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the conversion fails.
 */
export const montgomeryToRawPublicKey = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return montgomeryToRawPublicKeyInternal(
      curve,
      keyByteLength,
      curveName,
      jwkPublicKey,
    );
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Converts a JWK formatted Montgomery public key to a raw public key.
 *
 * @param {CurveFn} _curve - The curve function (unused in this implementation).
 * @param {number} keyByteLength - The expected byte length of the key.
 * @param {CurveName} curveName - The name of the curve to validate against.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const montgomeryToRawPublicKeyInternal = (
  _curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty === undefined || jwkPublicKey.kty === null) {
    throw new Error('Missing required parameter for kty');
  }

  if (jwkPublicKey.kty !== 'OKP') {
    throw new Error(`Invalid key type: ${jwkPublicKey.kty}, expected OKP`);
  }

  if (jwkPublicKey.crv === undefined || jwkPublicKey.crv === null) {
    throw new Error('Missing required parameter for crv');
  }

  if (jwkPublicKey.crv !== curveName) {
    throw new Error(
      `Invalid curve: ${jwkPublicKey.crv}, expected ${curveName}`,
    );
  }

  if (jwkPublicKey.x == null) {
    throw new Error('Missing required parameter for x');
  }

  if (typeof jwkPublicKey.x !== 'string') {
    throw new Error('Invalid parameter type for x');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPublicKey.x);
  } catch (e) {
    throw new Error('Malformed encoding for x');
  }

  if (decodedX.length !== keyByteLength) {
    throw new Error(
      `Invalid the length of the key data for x: ${decodedX.length}, expected ${keyByteLength}`,
    );
  }

  return decodedX;
};
