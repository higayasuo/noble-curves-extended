import { CurveFn } from '@noble/curves/abstract/weierstrass';

/**
 * Validates if a given public key is valid for the weierstrass curve.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {Uint8Array} publicKey - The public key to validate.
 * @returns {boolean} True if the public key is valid, false otherwise.
 */
export const weierstrassIsValidPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): boolean => {
  console.log(publicKey.length, curve.CURVE.nByteLength);
  // Check length
  if (publicKey.length !== curve.CURVE.nByteLength + 1) {
    return false;
  }

  // Check if public key is all zeros (invalid point)
  if (!publicKey.some((byte) => byte !== 0)) {
    return false;
  }

  return true;
};
