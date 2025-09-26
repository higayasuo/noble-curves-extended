import { CurveFn } from '@noble/curves/abstract/weierstrass';
import {
  CurveName,
  JwkPrivateKey,
  SignatureAlgorithmName,
} from '@/unified/types';
import { compareUint8Arrays, decodeBase64Url } from 'u8a-utils';
import { weierstrassToRawPublicKeyInternal } from './weierstrassToRawPublicKey';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a JWK formatted Weierstrass private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - Expected coordinate byte length (length of x and y in bytes).
 * @param {CurveName} curveName - Expected `crv` value in the JWK (e.g. 'P-256').
 * @param {SignatureAlgorithmName} signatureAlgorithmName - Expected `alg` value in the JWK (e.g. 'ES256').
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const weierstrassToRawPrivateKey = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  signatureAlgorithmName: SignatureAlgorithmName,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  try {
    return weierstrassToRawPrivateKeyInternal(
      curve,
      keyByteLength,
      curveName,
      signatureAlgorithmName,
      jwkPrivateKey,
    );
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to convert JWK to raw private key');
  }
};

/**
 * Internal function to convert a JWK formatted Weierstrass private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {number} keyByteLength - Expected coordinate byte length (length of x and y in bytes).
 * @param {CurveName} curveName - Expected `crv` value in the JWK (e.g. 'P-256').
 * @param {SignatureAlgorithmName} signatureAlgorithmName - Expected `alg` value in the JWK (e.g. 'ES256').
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 * @internal
 */
export const weierstrassToRawPrivateKeyInternal = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  signatureAlgorithmName: SignatureAlgorithmName,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  const publicKey = weierstrassToRawPublicKeyInternal(
    curve,
    keyByteLength,
    curveName,
    signatureAlgorithmName,
    jwkPrivateKey,
  );

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

  if (decodedD.length !== keyByteLength) {
    throw new Error(
      `Invalid the length of the key data for d: ${decodedD.length}, expected ${keyByteLength}`,
    );
  }

  if (!compareUint8Arrays(curve.getPublicKey(decodedD, false), publicKey)) {
    throw new Error(
      'The public key derived from the private key does not match the public key in the JWK',
    );
  }

  return decodedD;
};
