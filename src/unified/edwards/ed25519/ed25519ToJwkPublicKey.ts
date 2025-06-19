import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519IsValidPublicKey } from './ed25519IsValidPublicKey';
import type { JwkPublicKey } from '@/unified/types';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts an Ed25519 public key to a JWK format.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {JwkPublicKey} The public key in JWK format.
 * @throws {Error} Throws an error if the public key is invalid.
 */
export const ed25519ToJwkPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  if (!ed25519IsValidPublicKey(curve, publicKey)) {
    throw new Error('Public key is invalid');
  }

  return {
    kty: 'OKP',
    crv: 'Ed25519',
    alg: 'EdDSA',
    x: encodeBase64Url(publicKey),
  };
};
