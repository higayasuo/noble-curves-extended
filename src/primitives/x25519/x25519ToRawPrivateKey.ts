import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPrivateKey } from '../../types';
import { decodeBase64Url } from 'u8a-utils';
import { x25519IsValidPublicKey } from './x25519IsValidPublicKey';
import { x25519IsValidPrivateKey } from './x25519IsValidPrivateKey';

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
  if (jwkPrivateKey.kty !== 'OKP') {
    throw new Error('Invalid JWK: kty parameter must be OKP');
  }

  if (jwkPrivateKey.crv !== 'X25519') {
    throw new Error('Invalid JWK: crv parameter must be X25519');
  }

  if (!jwkPrivateKey?.x) {
    throw new Error('Invalid JWK: x parameter is missing');
  }

  if (typeof jwkPrivateKey.x !== 'string') {
    throw new Error('Invalid JWK: x parameter must be a string');
  }

  if (!jwkPrivateKey?.d) {
    throw new Error('Invalid JWK: d parameter is missing');
  }

  if (typeof jwkPrivateKey.d !== 'string') {
    throw new Error('Invalid JWK: d parameter must be a string');
  }

  if (jwkPrivateKey.alg && jwkPrivateKey.alg !== 'ECDH-ES') {
    throw new Error('Invalid JWK: alg parameter must be ECDH-ES');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPrivateKey.x);
  } catch (e) {
    throw new Error('Invalid JWK: malformed Base64URL in x parameter');
  }

  if (!x25519IsValidPublicKey(curve, decodedX)) {
    throw new Error('Invalid X25519 public key');
  }

  let decodedD!: Uint8Array;
  try {
    decodedD = decodeBase64Url(jwkPrivateKey.d);
  } catch (e) {
    throw new Error('Invalid JWK: malformed Base64URL in d parameter');
  }

  if (!x25519IsValidPrivateKey(curve, decodedD)) {
    throw new Error('Invalid X25519 private key');
  }

  return decodedD;
};
