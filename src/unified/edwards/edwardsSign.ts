import { CurveFn } from '@noble/curves/abstract/edwards';
import type { SignParams } from '@/unified/types';
import { isUint8Array, ensureUint8Array } from 'u8a-utils';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Signs a message using the edwards curve and a private key.
 *
 * @param {CurveFn} curve - The curve function used for signing.
 * @param {number} keyByteLength - The byte length of the private key.
 * @param {SignParams} params - An object containing the message and private key.
 * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @param {boolean} [params.recovered=false] - Indicates if the signature should be in recovered format.
 * @returns {Uint8Array} The signature as a Uint8Array.
 * @throws {Error} Throws an error if recovered signature is requested or if signing fails.
 */
export const edwardsSign = (
  curve: CurveFn,
  keyByteLength: number,
  { message, privateKey, recovered = false }: SignParams,
): Uint8Array => {
  if (recovered) {
    throw new Error('Recovered signature is not supported');
  }

  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    const seed =
      privateKey.length === keyByteLength * 2
        ? privateKey.slice(0, keyByteLength)
        : privateKey;
    return curve.sign(msg, seed);
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to sign message');
  }
};
