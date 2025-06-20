import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPublicKey } from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';

/**
 * Converts a JWK formatted Ed25519 public key to a raw public key.
 *
 * @param {CurveFn} _curve - The curve function used for conversion (unused).
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const ed25519ToRawPublicKey = (
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

  if (jwkPublicKey.crv !== 'Ed25519') {
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
    jwkPublicKey.alg !== 'EdDSA'
  ) {
    throw new Error('Invalid JWK: unsupported algorithm');
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
