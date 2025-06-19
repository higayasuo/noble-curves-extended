import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPublicKey } from '@/unified/types';
import { decodeBase64Url } from 'u8a-utils';
import { ed25519IsValidPublicKey } from './ed25519IsValidPublicKey';

/**
 * Converts a JWK (JSON Web Key) to a raw Ed25519 public key.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {JwkPublicKey} jwkPublicKey - The JWK to convert.
 * @returns {Uint8Array} The raw public key as a Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or the public key is invalid.
 */
export const ed25519ToRawPublicKey = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty !== 'OKP') {
    throw new Error('Invalid JWK: unsupported key type');
  }

  if (jwkPublicKey.crv !== 'Ed25519') {
    throw new Error('Invalid JWK: unsupported curve');
  }

  if (!jwkPublicKey?.x) {
    throw new Error('Invalid JWK: missing required parameter for x');
  }

  if (typeof jwkPublicKey.x !== 'string') {
    throw new Error('Invalid JWK: invalid parameter type for x');
  }

  if (jwkPublicKey.alg && jwkPublicKey.alg !== 'EdDSA') {
    throw new Error('Invalid JWK: unsupported algorithm');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPublicKey.x);
  } catch (e) {
    throw new Error('Invalid JWK: malformed encoding for x');
  }

  if (!ed25519IsValidPublicKey(curve, decodedX)) {
    throw new Error('Invalid JWK: invalid key data for x');
  }

  return decodedX;
};
