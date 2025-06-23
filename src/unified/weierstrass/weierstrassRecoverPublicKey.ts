import { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { RecoverPublicKeyParams } from '@/unified/types';
import { isUint8Array } from 'u8a-utils';
import { ensureUint8Array } from 'u8a-utils';
import { fromRawSignature } from '@/curves/weierstrass/fromRawSignature';

/**
 * Recovers a public key from a given signature and message using the Weierstrass curve.
 *
 * @param {CurveFn} curve - The curve function used for the recovery process.
 * @param {RecoverPublicKeyParams} params - An object containing the signature, message, and compression option.
 * @param {Uint8Array} params.signature - The signature used for recovery as a Uint8Array.
 * @param {Uint8Array} params.message - The message that was signed as a Uint8Array.
 * @param {boolean} [params.compressed=true] - Whether the recovered public key should be compressed.
 * @returns {Uint8Array} The recovered public key as a Uint8Array.
 * @throws {Error} Throws an error if the public key recovery fails.
 */
export const weierstrassRecoverPublicKey = (
  curve: CurveFn,
  { signature, message, compressed = true }: RecoverPublicKeyParams,
): Uint8Array => {
  try {
    const msg = isUint8Array(message) ? ensureUint8Array(message) : message;
    const msgHash = curve.CURVE.hash(msg);
    const sig = fromRawSignature(curve, signature);
    const point = sig.recoverPublicKey(msgHash);

    return point.toRawBytes(compressed);
  } catch (error) {
    console.error(error);
    throw new Error('Failed to recover public key');
  }
};
