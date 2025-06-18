import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPublicKey } from '../types';
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
    throw new Error('Invalid JWK: kty parameter must be OKP');
  }

  if (jwkPublicKey.crv !== 'Ed25519') {
    throw new Error('Invalid JWK: crv parameter must be Ed25519');
  }

  if (!jwkPublicKey?.x) {
    throw new Error('Invalid JWK: x parameter is missing');
  }

  if (typeof jwkPublicKey.x !== 'string') {
    throw new Error('Invalid JWK: x parameter must be a string');
  }

  if (jwkPublicKey.alg && jwkPublicKey.alg !== 'EdDSA') {
    throw new Error('Invalid JWK: alg parameter must be EdDSA');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPublicKey.x);
  } catch (e) {
    throw new Error('Invalid JWK: malformed Base64URL in x parameter');
  }

  if (!ed25519IsValidPublicKey(curve, decodedX)) {
    throw new Error('Ed25519 public key is invalid');
  }

  return decodedX;
};
