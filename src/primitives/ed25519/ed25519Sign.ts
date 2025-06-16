import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519IsValidPrivateKey } from './ed25519IsValidPrivateKey';
import type { SignParams } from '../../types';
import { isUint8Array } from 'u8a-utils';
import { ensureUint8Array } from 'u8a-utils';

/**
 * Signs a message using the Ed25519 curve and a private key.
 *
 * @param {CurveFn} curve - The curve function used to sign the message.
 * @param {SignParams} params - An object containing the message and private key.
 * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @returns {Uint8Array} The signature as a Uint8Array.
 * @throws {Error} Throws an error if the private key is invalid or if signing fails.
 */
export const ed25519Sign = (
  curve: CurveFn,
  { message, privateKey }: SignParams,
): Uint8Array => {
  if (!ed25519IsValidPrivateKey(curve, privateKey)) {
    throw new Error('Ed25519 private key is invalid');
  }

  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    return curve.sign(msg, privateKey);
  } catch (error) {
    console.error(error);
    throw new Error('Failed to sign message');
  }
};
