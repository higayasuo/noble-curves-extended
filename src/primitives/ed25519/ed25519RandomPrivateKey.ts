import { CurveFn } from '@noble/curves/abstract/edwards';

/**
 * Generates a random private key for the ed25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key.
 */
export const ed25519RandomPrivateKey = (curve: CurveFn): Uint8Array => {
  return curve.utils.randomPrivateKey();
};
