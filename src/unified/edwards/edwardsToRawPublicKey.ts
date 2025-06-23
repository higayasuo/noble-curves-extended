import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPublicKey } from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';
import { getEdwardsCurveName } from '@/curves/edwards';

/**
 * Converts a JWK formatted edwards public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the conversion fails.
 */
export const edwardsToRawPublicKey = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return edwardsToRawPublicKeyInternal(curve, jwkPublicKey);
  } catch (e) {
    console.error(e);
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Converts a JWK formatted edwards public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const edwardsToRawPublicKeyInternal = (
  curve: CurveFn,
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

  if (jwkPublicKey.crv !== getEdwardsCurveName(curve)) {
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

  if (decodedX.length !== curve.CURVE.nByteLength) {
    throw new Error('Invalid JWK: invalid key data for x');
  }

  return decodedX;
};
