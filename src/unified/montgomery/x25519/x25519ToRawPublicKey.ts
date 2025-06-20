import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPublicKey } from '../../types';
import { decodeBase64Url } from 'u8a-utils';

/**
 * Converts a JWK (JSON Web Key) to a raw X25519 public key.
 *
 * @param {CurveFn} _curve - The curve function used for conversion (unused).
 * @param {JwkPublicKey} jwkPublicKey - The JWK to convert.
 * @returns {Uint8Array} The raw public key as a Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or the public key is invalid.
 */
export const x25519ToRawPublicKey = (
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

  if (
    jwkPublicKey.alg !== undefined &&
    jwkPublicKey.alg !== null &&
    jwkPublicKey.alg !== 'ECDH-ES'
  ) {
    throw new Error('Invalid JWK: unsupported algorithm');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPublicKey.x);
    console.log('decodedX', decodedX);
  } catch (e) {
    throw new Error('Invalid JWK: malformed encoding for x');
  }

  if (decodedX.length !== 32) {
    throw new Error('Invalid JWK: invalid key data for x');
  }

  return decodedX;
};
