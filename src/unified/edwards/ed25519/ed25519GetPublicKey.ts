import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519IsValidPrivateKey } from './ed25519IsValidPrivateKey';

/**
 * Generates a public key for the ed25519 curve from a given private key.
 *
 * @param {CurveFn} curve - The curve function used to generate the public key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @param {boolean} [compressed=true] - Indicates if the public key should be compressed.
 * Note: ed25519 only supports compressed public keys.
 * @returns {Uint8Array} The generated public key as a Uint8Array.
 * @throws {Error} Throws an error if uncompressed public keys are requested or if the private key is invalid.
 */
export const ed25519GetPublicKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array => {
  if (!compressed) {
    throw new Error('Ed25519 does not support uncompressed public keys');
  }

  if (!ed25519IsValidPrivateKey(curve, privateKey)) {
    throw new Error('Ed25519 private key is invalid');
  }

  return curve.getPublicKey(privateKey);
};
