import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPrivateKey } from '../../types';
import { compareUint8Arrays, decodeBase64Url } from 'u8a-utils';
import {
  x25519ToRawPublicKey,
  x25519ToRawPublicKeyInternal,
} from './x25519ToRawPublicKey';

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
  try {
    return x25519ToRawPrivateKeyInternal(curve, jwkPrivateKey);
  } catch (e) {
    console.error(e);
    throw new Error('Failed to convert JWK to raw private key');
  }
};

/**
 * Internal function to convert a JWK formatted X25519 private key to a raw private key.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {JwkPrivateKey} jwkPrivateKey - The private key in JWK format.
 * @returns {Uint8Array} The private key as a raw Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or if the decoding fails.
 * @internal
 */
export const x25519ToRawPrivateKeyInternal = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  const publicKey = x25519ToRawPublicKeyInternal(curve, jwkPrivateKey);

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

  if (!compareUint8Arrays(curve.getPublicKey(decodedD), publicKey)) {
    throw new Error('Invalid JWK: invalid key data for d');
  }

  return decodedD;
};
