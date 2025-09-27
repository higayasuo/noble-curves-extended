import { CurveFn } from '@noble/curves/abstract/weierstrass';
import {
  CurveName,
  JwkPrivateKey,
  SignatureAlgorithmName,
} from '@/unified/types';
import { weierstrassToJwkPublickKey } from './weierstrassToJwkPublickKey';
import { encodeBase64Url } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Converts a Weierstrass private key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key.
 * @param {number} keyByteLength - The expected byte length of each coordinate (x, y).
 * @param {CurveName} curveName - The name of the curve to validate against.
 * @param {SignatureAlgorithmName} signatureAlgorithmName - The signature algorithm name for the JWK.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @returns {JwkPrivateKey} The private key in JWK format.
 * @throws {Error} Throws an error if the private key conversion fails.
 */
export const weierstrassToJwkPrivateKey = (
  curve: CurveFn,
  keyByteLength: number,
  curveName: CurveName,
  signatureAlgorithmName: SignatureAlgorithmName,
  privateKey: Uint8Array,
): JwkPrivateKey => {
  try {
    const publicKey = curve.getPublicKey(privateKey);
    const jwkPublicKey = weierstrassToJwkPublickKey(
      curve,
      keyByteLength,
      curveName,
      signatureAlgorithmName,
      publicKey,
    );

    return {
      ...jwkPublicKey,
      d: encodeBase64Url(privateKey),
    };
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to convert private key to JWK');
  }
};
