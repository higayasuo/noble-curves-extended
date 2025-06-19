import { CurveFn } from '@noble/curves/abstract/weierstrass';

/**
 * Validates if a given private key is valid for the weierstrass curve.
 *
 * @param {CurveFn} curve - The curve function used to validate the private key.
 * @param {Uint8Array} privateKey - The private key to validate.
 * @returns {boolean} True if the private key is valid, false otherwise.
 */
export const weierstrassIsValidPrivateKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
): boolean => {
  return curve.utils.isValidPrivateKey(privateKey);
};
