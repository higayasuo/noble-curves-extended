import { CurveFn } from '@noble/curves/abstract/edwards';
import type { VerifyParams } from '@/unified/types';
import { isUint8Array } from 'u8a-utils';
import { ensureUint8Array } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Verifies a signature using the edwards curve and a public key.
 *
 * @param {CurveFn} curve - The curve function used for verification.
 * @param {VerifyParams} params - An object containing the signature, message, and public key.
 * @param {Uint8Array} params.signature - The signature to be verified as a Uint8Array.
 * @param {Uint8Array} params.message - The message that was signed as a Uint8Array.
 * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
export const edwardsVerify = (
  curve: CurveFn,
  { signature, message, publicKey }: VerifyParams,
): boolean => {
  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    return curve.verify(signature, msg, publicKey);
  } catch (error) {
    console.log(getErrorMessage(error));
    return false;
  }
};
