import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519IsValidPrivateKey } from './ed25519IsValidPrivateKey';

/**
 * Signs a message using the Ed25519 algorithm.
 *
 * @param {CurveFn} curve - The curve function used to sign the message.
 * @param {Uint8Array} message - The message to be signed.
 * @param {Uint8Array} privateKey - The private key used for signing.
 * @returns {Uint8Array} The signature as a Uint8Array.
 * @throws {Error} Throws an error if the private key is invalid.
 */
export const ed25519Sign = (
  curve: CurveFn,
  message: Uint8Array,
  privateKey: Uint8Array,
): Uint8Array => {
  if (!ed25519IsValidPrivateKey(curve, privateKey)) {
    throw new Error('Ed25519 private key is invalid');
  }

  return curve.sign(message, privateKey);
};
