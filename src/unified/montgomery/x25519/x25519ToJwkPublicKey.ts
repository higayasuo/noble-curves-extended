import { CurveFn } from '@noble/curves/abstract/montgomery';
import { x25519IsValidPublicKey } from './x25519IsValidPublicKey';
import type { JwkPublicKey } from '../../types';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts an X25519 public key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the public key is invalid.
 */
export const x25519ToJwkPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  if (!x25519IsValidPublicKey(curve, publicKey)) {
    throw new Error('X25519 public key is invalid');
  }

  return {
    kty: 'OKP',
    crv: 'X25519',
    x: encodeBase64Url(publicKey),
    alg: 'ECDH-ES',
  };
};
