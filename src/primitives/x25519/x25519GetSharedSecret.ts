import { CurveFn } from '@noble/curves/abstract/montgomery';
import { x25519IsValidPrivateKey } from './x25519IsValidPrivateKey';
import { x25519IsValidPublicKey } from './x25519IsValidPublicKey';

/**
 * Computes the shared secret for the x25519 curve using a given private key and public key.
 *
 * @param {CurveFn} curve - The curve function used to compute the shared secret.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @param {Uint8Array} publicKey - The public key as a Uint8Array.
 * @returns {Uint8Array} The computed shared secret as a Uint8Array.
 * @throws {Error} Throws an error if the private key or public key is invalid.
 */
export const x25519GetSharedSecret = (
  curve: CurveFn,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array => {
  if (!x25519IsValidPrivateKey(curve, privateKey)) {
    throw new Error('Invalid X25519 private key');
  }

  if (!x25519IsValidPublicKey(curve, publicKey)) {
    throw new Error('Invalid X25519 public key');
  }

  return curve.getSharedSecret(privateKey, publicKey);
};
