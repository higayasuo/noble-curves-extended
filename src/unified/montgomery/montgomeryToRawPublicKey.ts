import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPublicKey } from '../types';
import { decodeBase64Url } from 'u8a-utils';
import { getMontgomeryCurveName } from '@/curves/montgomery';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted Montgomery public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the conversion fails.
 */
export const montgomeryToRawPublicKey = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return montgomeryToRawPublicKeyInternal(curve, jwkPublicKey);
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Converts a JWK formatted Montgomery public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const montgomeryToRawPublicKeyInternal = (
  curve: CurveFn,
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

  const expectedCrv = getMontgomeryCurveName(curve);
  if (jwkPublicKey.crv !== expectedCrv) {
    throw new Error(
      `Invalid curve: ${jwkPublicKey.crv}, expected ${expectedCrv}`,
    );
  }

  if (jwkPublicKey.x === undefined || jwkPublicKey.x === null) {
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

  if (decodedX.length !== curve.GuBytes.length) {
    throw new Error(
      `Invalid the length of the key data for x: ${decodedX.length}, expected ${curve.GuBytes.length}`,
    );
  }

  return decodedX;
};
