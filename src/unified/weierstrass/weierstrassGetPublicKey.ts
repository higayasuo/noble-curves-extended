import { getErrorMessage } from '@/utils/getErrorMessage';
import { CurveFn } from '@noble/curves/abstract/weierstrass';

/**
 * Generates a public key for the weierstrass curve from a given private key.
 *
 * @param {CurveFn} curve - The curve function used to generate the public key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @param {boolean} [compressed=true] - Indicates if the public key should be compressed.
 * @returns {Uint8Array} The generated public key as a Uint8Array.
 * @throws {Error} Throws an error if uncompressed public keys are requested or if the private key is invalid.
 */
export const weierstrassGetPublicKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array => {
  try {
    return curve.getPublicKey(privateKey, compressed);
  } catch (e) {
    console.log(getErrorMessage(e));
    throw new Error('Failed to get public key');
  }
};
