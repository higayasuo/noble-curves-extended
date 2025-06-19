import { CurveFn } from '@noble/curves/abstract/montgomery';

/**
 * Validates if a given private key is valid for the x25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to validate the private key.
 * @param {Uint8Array} privateKey - The private key to validate.
 * @returns {boolean} True if the private key is valid, false otherwise.
 */
export const x25519IsValidPrivateKey = (
  _curve: CurveFn,
  privateKey: Uint8Array,
): boolean => {
  if (privateKey.length !== 32) {
    return false;
  }

  // Check if private key is all zeros
  if (!privateKey.some((byte) => byte !== 0)) {
    return false;
  }

  return true;
};
