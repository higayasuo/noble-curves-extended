import { getErrorMessage } from '@/utils/getErrorMessage';
import { CurveFn } from '@noble/curves/abstract/edwards';

/**
 * Generates a random private key for the edwards curve.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key as a Uint8Array.
 * @throws {Error} Throws an error if the private key generation fails.
 */
export const edwardsRandomPrivateKey = (curve: CurveFn): Uint8Array => {
  try {
    return curve.utils.randomPrivateKey();
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to generate random private key');
  }
};
