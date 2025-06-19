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
  // Check if public key is all zeros
  if (!publicKey.some((byte) => byte !== 0)) {
    return false;
  }

  try {
    const point = curve.Point.fromHex(publicKey);
    point.assertValidity();

    return true;
  } catch {
    return false;
  }
};
