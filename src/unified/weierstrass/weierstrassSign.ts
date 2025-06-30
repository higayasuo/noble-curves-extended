import { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { SignParams } from '@/unified/types';
import { isUint8Array, ensureUint8Array } from 'u8a-utils';
import { toRawRecoveredSignature } from '@/curves/weierstrass/toRawRecoveredSignature';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Signs a message using the Weierstrass curve and a private key.
 *
 * @param {CurveFn} curve - The curve function used for signing.
 * @param {SignParams} params - An object containing the message and private key.
 * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @param {boolean} [params.recovered=false] - Indicates if the signature should be in recovered format. If true, the signature will be returned in the format of a raw signature with the recovery byte.
 * @returns {Uint8Array} The signature as a Uint8Array.
 * @throws {Error} Throws an error if signing fails.
 */
export const weierstrassSign = (
  curve: CurveFn,
  { message, privateKey, recovered = false }: SignParams,
): Uint8Array => {
  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    const signature = curve.sign(msg, privateKey, { prehash: true });

    if (recovered) {
      return toRawRecoveredSignature(signature);
    }

    return signature.toCompactRawBytes();
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to sign message');
  }
};
