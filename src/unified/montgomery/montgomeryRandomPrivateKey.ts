import { CurveFn } from '@noble/curves/abstract/montgomery';

/**
 * Generates a random private key for the Montgomery curve.
 *
 * This function utilizes the curve's utility method to generate a random private key.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key.
 * @throws {Error} Throws an error if the random private key generation fails.
 */
export const montgomeryRandomPrivateKey = (curve: CurveFn): Uint8Array => {
  try {
    return curve.utils.randomPrivateKey();
  } catch (error) {
    console.error(error);
    throw new Error('Failed to generate random private key');
  }
};
