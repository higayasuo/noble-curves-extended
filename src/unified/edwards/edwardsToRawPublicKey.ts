import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPublicKey } from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';
import { getEdwardsCurveName } from '@/curves/edwards';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted edwards public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - The expected byte length of the public key.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the conversion fails.
 */
export const edwardsToRawPublicKey = (
  curve: CurveFn,
  keyByteLength: number,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkPublicKey);
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Converts a JWK formatted edwards public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - The expected byte length of the public key.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const edwardsToRawPublicKeyInternal = (
  curve: CurveFn,
  keyByteLength: number,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty == null) {
    throw new Error('Missing required parameter for kty');
  }

  if (jwkPublicKey.kty !== 'OKP') {
    throw new Error(`Invalid key type: ${jwkPublicKey.kty}, expected OKP`);
  }

  if (jwkPublicKey.crv === undefined || jwkPublicKey.crv === null) {
    throw new Error('Missing required parameter for crv');
  }

  const expectedCrv = getEdwardsCurveName(curve);
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

  if (
    jwkPublicKey.alg !== undefined &&
    jwkPublicKey.alg !== null &&
    jwkPublicKey.alg !== 'EdDSA'
  ) {
    throw new Error(`Invalid algorithm: ${jwkPublicKey.alg}, expected EdDSA`);
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
