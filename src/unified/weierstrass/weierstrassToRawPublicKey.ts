import { CurveFn } from '@noble/curves/abstract/weierstrass';
import {
  CurveName,
  JwkPublicKey,
  SignatureAlgorithmName,
} from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted Weierstrass public key to a raw uncompressed public key.
 *
 * @param {CurveFn} curve - The curve implementation (unused in the current implementation).
 * @param {number} keyByteLength - Expected coordinate byte length (length of x and y in bytes).
 * @param {CurveName} curveName - Expected `crv` value in the JWK (e.g. 'P-256').
 * @param {SignatureAlgorithmName} signatureAlgorithmName - Expected `alg` value in the JWK (e.g. 'ES256').
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The raw uncompressed public key as a Uint8Array: [0x04 || x || y].
 * @throws {Error} If required parameters are missing, malformed, mismatched, or decoding fails.
 */
export const weierstrassToRawPublicKey = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  signatureAlgorithmName: SignatureAlgorithmName,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  try {
    return weierstrassToRawPublicKeyInternal(
      curve,
      keyByteLength,
      curveName,
      signatureAlgorithmName,
      jwkPublicKey,
    );
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw public key');
  }
};

/**
 * Internal conversion from a JWK formatted Weierstrass public key to raw uncompressed form.
 *
 * @param {CurveFn} _curve - The curve implementation (unused in the current implementation).
 * @param {number} keyByteLength - Expected coordinate byte length (length of x and y in bytes).
 * @param {CurveName} curveName - Expected `crv` value in the JWK (e.g. 'P-256').
 * @param {SignatureAlgorithmName} signatureAlgorithmName - Expected `alg` value in the JWK (e.g. 'ES256').
 * @param {JwkPublicKey} jwkPublicKey - The public key in JWK format.
 * @returns {Uint8Array} The raw uncompressed public key as a Uint8Array: [0x04 || x || y].
 * @throws {Error} If required parameters are missing, malformed, mismatched, or decoding fails.
 * @internal
 */
export const weierstrassToRawPublicKeyInternal = (
  _curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  signatureAlgorithmName: SignatureAlgorithmName,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty === undefined || jwkPublicKey.kty === null) {
    throw new Error('Missing required parameter for kty');
  }

  if (jwkPublicKey.kty !== 'EC') {
    throw new Error(`Invalid key type: ${jwkPublicKey.kty}, expected EC`);
  }

  if (jwkPublicKey.crv == null) {
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

  if (jwkPublicKey.y == null) {
    throw new Error('Missing required parameter for y');
  }

  if (typeof jwkPublicKey.y !== 'string') {
    throw new Error('Invalid parameter type for y');
  }

  if (jwkPublicKey.alg != null && jwkPublicKey.alg !== signatureAlgorithmName) {
    throw new Error(
      `Invalid algorithm: ${jwkPublicKey.alg}, expected ${signatureAlgorithmName}`,
    );
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

  let decodedY!: Uint8Array;
  try {
    decodedY = decodeBase64Url(jwkPublicKey.y);
  } catch (e) {
    throw new Error('Malformed encoding for y');
  }

  if (decodedY.length !== keyByteLength) {
    throw new Error(
      `Invalid the length of the key data for y: ${decodedY.length}, expected ${keyByteLength}`,
    );
  }

  return new Uint8Array([0x04, ...decodedX, ...decodedY]);
};
