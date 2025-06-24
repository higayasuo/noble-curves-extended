import { CurveFn } from '@noble/curves/abstract/montgomery';

/**
 * Generates a public key for the Montgomery curve from a given private key.
 *
 * @param {CurveFn} curve - The curve function used to generate the public key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @param {boolean} [compressed=true] - Indicates if the public key should be compressed.
 * Note: x25519 only supports compressed public keys.
 * @returns {Uint8Array} The generated public key as a Uint8Array.
 * @throws {Error} Throws an error if uncompressed public keys are requested or if the private key is invalid.
 */
export const montgomeryGetPublicKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array => {
  if (!compressed) {
    throw new Error('Uncompressed public key is not supported');
  }

  try {
    return curve.getPublicKey(privateKey);
  } catch (error) {
    console.error(error);
    throw new Error('Failed to get public key');
  }
};
