import { CurveFn } from '@noble/curves/abstract/montgomery';
import { adjustScalarBytes } from '../../edwards/ed25519';

/**
 * Generates a random private key for the x25519 curve, applying adjustScalarBytes for RFC 7748 compliance.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated and adjusted private key.
 */
export const x25519RandomPrivateKey = (curve: CurveFn): Uint8Array => {
  const privateKey = curve.utils.randomPrivateKey();
  return adjustScalarBytes(privateKey);
};
