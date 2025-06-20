import { CurveFn } from '@noble/curves/abstract/edwards';
import type { SignParams } from '@/unified/types';
import { isUint8Array, ensureUint8Array } from 'u8a-utils';

/**
 * Signs a message using the Ed25519 curve and a private key.
 *
 * @param {CurveFn} curve - The curve function used for signing.
 * @param {SignParams} params - An object containing the message and private key.
 * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @param {boolean} [params.recoverable=false] - Indicates if the signature should be recoverable.
 * @returns {Uint8Array} The signature as a Uint8Array.
 * @throws {Error} Throws an error if recoverable signature is requested or if signing fails.
 */
export const ed25519Sign = (
  curve: CurveFn,
  { message, privateKey, recoverable = false }: SignParams,
): Uint8Array => {
  if (recoverable) {
    throw new Error('Recoverable signature is not supported');
  }

  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    const seed =
      privateKey.length === 64 ? privateKey.slice(0, 32) : privateKey;
    return curve.sign(msg, seed);
  } catch (error) {
    console.error(error);
    throw new Error('Failed to sign message');
  }
};
