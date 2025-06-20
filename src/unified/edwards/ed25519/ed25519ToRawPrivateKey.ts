import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPrivateKey } from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';
import { ed25519ToRawPublicKey } from './ed25519ToRawPublicKey';

/**
 * Converts a JWK formatted Ed25519 private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 */
export const ed25519ToRawPrivateKey = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  ed25519ToRawPublicKey(curve, jwkPrivateKey);

  if (jwkPrivateKey.d === undefined || jwkPrivateKey.d === null) {
    throw new Error('Invalid JWK: missing required parameter for d');
  }

  if (typeof jwkPrivateKey.d !== 'string') {
    throw new Error('Invalid JWK: invalid parameter type for d');
  }

  let decodedD!: Uint8Array;
  try {
    decodedD = decodeBase64Url(jwkPrivateKey.d);
  } catch (e) {
    throw new Error('Invalid JWK: malformed encoding for d');
  }

  if (decodedD.length !== 32) {
    throw new Error('Invalid JWK: invalid key data for d');
  }

  return decodedD;
};
