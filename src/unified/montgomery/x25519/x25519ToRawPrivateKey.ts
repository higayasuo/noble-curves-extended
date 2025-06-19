import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPrivateKey } from '../../types';
import { decodeBase64Url } from 'u8a-utils';
import { x25519IsValidPrivateKey } from './x25519IsValidPrivateKey';
import { x25519ToRawPublicKey } from './x25519ToRawPublicKey';

/**
 * Converts a JWK (JSON Web Key) to a raw X25519 private key.
 *
 * @param {CurveFn} curve - The curve function used to validate the keys.
 * @param {JwkPrivateKey} jwkPrivateKey - The JWK to convert.
 * @returns {Uint8Array} The raw private key as a Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or the private key is invalid.
 */
export const x25519ToRawPrivateKey = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  x25519ToRawPublicKey(curve, jwkPrivateKey);

  if (!jwkPrivateKey.d) {
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

  if (!x25519IsValidPrivateKey(curve, decodedD)) {
    throw new Error('Invalid JWK: invalid key data for d');
  }

  return decodedD;
};
