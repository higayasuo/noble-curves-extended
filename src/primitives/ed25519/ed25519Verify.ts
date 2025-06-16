import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519IsValidPublicKey } from './ed25519IsValidPublicKey';
import type { VerifyParams } from '../../types';

/**
 * Verifies a signature using the Ed25519 curve and a public key.
 *
 * @param {CurveFn} curve - The curve function used to verify the signature.
 * @param {VerifyParams} params - An object containing the signature, message, and public key.
 * @param {Uint8Array} params.signature - The signature to be verified as a Uint8Array.
 * @param {Uint8Array} params.message - The message that was signed as a Uint8Array.
 * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
 * @returns {boolean} True if the signature is valid, false otherwise.
 * @throws {Error} Throws an error if the public key is invalid or if verification fails.
 */
export const ed25519Verify = (
  curve: CurveFn,
  { signature, message, publicKey }: VerifyParams,
): boolean => {
  if (!ed25519IsValidPublicKey(curve, publicKey)) {
    throw new Error('Ed25519 public key is invalid');
  }

  return curve.verify(signature, message, publicKey);
};
