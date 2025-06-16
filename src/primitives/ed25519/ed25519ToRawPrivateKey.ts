import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPrivateKey } from '../../types';
import { decodeBase64Url } from 'u8a-utils';
import { ed25519IsValidPublicKey } from './ed25519IsValidPublicKey';
import { ed25519IsValidPrivateKey } from './ed25519IsValidPrivateKey';

/**
 * Converts a JWK (JSON Web Key) to a raw Ed25519 private key.
 *
 * @param {CurveFn} curve - The curve function used to validate the keys.
 * @param {JwkPrivateKey} jwkPrivateKey - The JWK to convert.
 * @returns {Uint8Array} The raw private key as a Uint8Array.
 * @throws {Error} Throws an error if the JWK is invalid or the private key is invalid.
 */
export const ed25519ToRawPrivateKey = (
  curve: CurveFn,
  jwkPrivateKey: JwkPrivateKey,
): Uint8Array => {
  if (jwkPrivateKey.kty !== 'OKP') {
    throw new Error('Invalid JWK: kty parameter must be OKP');
  }

  if (jwkPrivateKey.crv !== 'Ed25519') {
    throw new Error('Invalid JWK: crv parameter must be Ed25519');
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

  if (jwkPrivateKey.alg && jwkPrivateKey.alg !== 'EdDSA') {
    throw new Error('Invalid JWK: alg parameter must be EdDSA');
  }

  let decodedX!: Uint8Array;
  try {
    decodedX = decodeBase64Url(jwkPrivateKey.x);
  } catch (e) {
    throw new Error('Invalid JWK: malformed Base64URL in x parameter');
  }

  if (!ed25519IsValidPublicKey(curve, decodedX)) {
    throw new Error('Ed25519 public key is invalid');
  }

  let decodedD!: Uint8Array;
  try {
    decodedD = decodeBase64Url(jwkPrivateKey.d);
  } catch (e) {
    throw new Error('Invalid JWK: malformed Base64URL in d parameter');
  }

  if (!ed25519IsValidPrivateKey(curve, decodedD)) {
    throw new Error('Ed25519 private key is invalid');
  }

  return decodedD;
};
