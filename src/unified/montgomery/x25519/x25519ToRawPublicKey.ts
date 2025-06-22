import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPublicKey } from '../../types';
import { decodeBase64Url } from 'u8a-utils';

/**
 * Converts a JWK formatted X25519 public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the conversion fails.
 */
export const x25519ToRawPublicKey = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return x25519ToRawPublicKeyInternal(curve, jwkPublicKey);
  } catch (e) {
    console.error(e);
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Converts a JWK formatted X25519 public key to a raw public key.
 *
 * @param {CurveFn} _curve - The curve function used for conversion (unused).
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const x25519ToRawPublicKeyInternal = (
  _curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty === undefined || jwkPublicKey.kty === null) {
    throw new Error('Invalid JWK: missing required parameter for kty');
  }

  if (jwkPublicKey.kty !== 'OKP') {
    throw new Error('Invalid JWK: unsupported key type');
  }

  if (jwkPublicKey.crv === undefined || jwkPublicKey.crv === null) {
    throw new Error('Invalid JWK: missing required parameter for crv');
  }

  if (jwkPublicKey.crv !== 'X25519') {
    throw new Error('Invalid JWK: unsupported curve');
  }

  if (jwkPublicKey.x === undefined || jwkPublicKey.x === null) {
    throw new Error('Invalid JWK: missing required parameter for x');
  }

  if (typeof jwkPublicKey.x !== 'string') {
    throw new Error('Invalid JWK: invalid parameter type for x');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPublicKey.x);
  } catch (e) {
    throw new Error('Invalid JWK: malformed encoding for x');
  }

  if (decodedX.length !== 32) {
    throw new Error('Invalid JWK: invalid key data for x');
  }

  return decodedX;
};
