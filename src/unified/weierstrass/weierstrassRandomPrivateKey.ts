import { CurveFn } from '@noble/curves/abstract/weierstrass';

/**
 * Generates a random private key for the Weierstrass curve.
 *
 * This function utilizes the curve's utility method to generate a random private key.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key.
 */
export const weierstrassRandomPrivateKey = (curve: CurveFn): Uint8Array => {
  try {
    return curve.utils.randomPrivateKey();
  } catch (e) {
    throw new Error(`Failed to generate random private key`);
  }
};
