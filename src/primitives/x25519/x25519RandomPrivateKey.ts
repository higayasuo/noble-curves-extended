import { CurveFn } from '@noble/curves/abstract/montgomery';
import { adjustScalarBytes } from '../../ed25519/ed25519';

/**
 * Generates a random private key for the x25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key.
 */
export const x25519RandomPrivateKey = (curve: CurveFn): Uint8Array => {
  const privateKey = curve.utils.randomPrivateKey();
  return adjustScalarBytes(privateKey);
};
