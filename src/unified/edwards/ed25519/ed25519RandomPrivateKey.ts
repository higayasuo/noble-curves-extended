import { CurveFn } from '@noble/curves/abstract/edwards';

/**
 * Generates a random private key for the Ed25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key as a Uint8Array.
 * @throws {Error} Throws an error if the private key generation fails.
 */
export const ed25519RandomPrivateKey = (curve: CurveFn): Uint8Array => {
  try {
    return curve.utils.randomPrivateKey();
  } catch (error) {
    console.error(error);
    throw new Error('Failed to generate random private key');
  }
};
