import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { JwkPublicKey } from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';
import { getWeierstrassCurveName } from '@/curves/weierstrass/getWeierstrassCurveName';
import { getWeierstrassSignatureAlgorithm } from '@/curves/weierstrass/getWeierstrassSignatureAlgorithm';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted Weierstrass public key to a raw public key.
 *
 * @param {CurveFn} _curve - The curve function used for conversion (unused).
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const weierstrassToRawPublicKey = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return weierstrassToRawPublicKeyInternal(curve, jwkPublicKey);
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Converts a JWK formatted Weierstrass public key to a raw public key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The public key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const weierstrassToRawPublicKeyInternal = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty === undefined || jwkPublicKey.kty === null) {
    throw new Error('Missing required parameter for kty');
  }

  if (jwkPublicKey.kty !== 'EC') {
    throw new Error(`Invalid key type: ${jwkPublicKey.kty}, expected EC`);
  }

  if (jwkPublicKey.crv === undefined || jwkPublicKey.crv === null) {
    throw new Error('Missing required parameter for crv');
  }

  const expectedCrv = getWeierstrassCurveName(curve);
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

  if (jwkPublicKey.y === undefined || jwkPublicKey.y === null) {
    throw new Error('Missing required parameter for y');
  }

  if (typeof jwkPublicKey.y !== 'string') {
    throw new Error('Invalid parameter type for y');
  }

  const expectedAlg = getWeierstrassSignatureAlgorithm(curve);
  if (
    jwkPublicKey.alg !== undefined &&
    jwkPublicKey.alg !== null &&
    jwkPublicKey.alg !== expectedAlg
  ) {
    throw new Error(
      `Invalid algorithm: ${jwkPublicKey.alg}, expected ${expectedAlg}`,
    );
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPublicKey.x);
  } catch (e) {
    throw new Error('Malformed encoding for x');
  }

  if (decodedX.length !== curve.CURVE.nByteLength) {
    throw new Error(
      `Invalid the length of the key data for x: ${decodedX.length}, expected ${curve.CURVE.nByteLength}`,
    );
  }

  let decodedY!: Uint8Array;
  try {
    decodedY = decodeBase64Url(jwkPublicKey.y);
  } catch (e) {
    throw new Error('Malformed encoding for y');
  }

  if (decodedY.length !== curve.CURVE.nByteLength) {
    throw new Error(
      `Invalid the length of the key data for y: ${decodedY.length}, expected ${curve.CURVE.nByteLength}`,
    );
  }

  return new Uint8Array([0x04, ...decodedX, ...decodedY]);
};
