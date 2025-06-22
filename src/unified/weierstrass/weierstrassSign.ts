import { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { SignParams } from '@/unified/types';
import { isUint8Array, ensureUint8Array } from 'u8a-utils';

/**
 * Signs a message using the Weierstrass curve and a private key.
 *
 * @param {CurveFn} curve - The curve function used for signing.
 * @param {SignParams} params - An object containing the message and private key.
 * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @param {boolean} [params.recoverable=false] - Indicates if the signature should be recoverable.
 * @returns {Uint8Array} The signature as a Uint8Array.
 * @throws {Error} Throws an error if recoverable signature is requested or if signing fails.
 */
export const weierstrassSign = (
  curve: CurveFn,
  { message, privateKey, recoverable = false }: SignParams,
): Uint8Array => {
  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    const signature = curve.sign(msg, privateKey, { prehash: true });
    const rawSignature = signature.toCompactRawBytes();

    if (recoverable) {
      const sig = new Uint8Array(rawSignature.length + 1);
      sig.set(rawSignature);
      sig[sig.length - 1] = signature.recovery;

      return sig;
    }

    return rawSignature;
  } catch (error) {
    console.error(error);
    throw new Error('Failed to sign message');
  }
};
