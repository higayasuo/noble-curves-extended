import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPublicKey } from '../../types';
import { decodeBase64Url } from 'u8a-utils';
import { x25519IsValidPublicKey } from './x25519IsValidPublicKey';

/**
 * Converts a JWK (JSON Web Key) to a raw X25519 public key.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {JwkPublicKey} jwkPublicKey - The JWK to convert.
 * @returns {Uint8Array} The raw public key as a Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or the public key is invalid.
 */
export const x25519ToRawPublicKey = (
  curve: CurveFn,
  jwkPublicKey: JwkPublicKey,
): Uint8Array => {
  if (jwkPublicKey.kty !== 'OKP') {
    throw new Error('Invalid JWK: kty parameter must be OKP');
  }

  if (jwkPublicKey.crv !== 'X25519') {
    throw new Error('Invalid JWK: crv parameter must be X25519');
  }

  if (!jwkPublicKey?.x) {
    throw new Error('Invalid JWK: x parameter is missing');
  }

  if (typeof jwkPublicKey.x !== 'string') {
    throw new Error('Invalid JWK: x parameter must be a string');
  }

  if (jwkPublicKey.alg && jwkPublicKey.alg !== 'ECDH-ES') {
    throw new Error('Invalid JWK: alg parameter must be ECDH-ES');
  }

  let decoded!: Uint8Array;
  try {
    decoded = decodeBase64Url(jwkPublicKey.x);
  } catch (e) {
    throw new Error('Invalid JWK: malformed Base64URL in x parameter');
  }

  if (!x25519IsValidPublicKey(curve, decoded)) {
    throw new Error('Invalid JWK: public key is invalid');
  }

  return decoded;
};
