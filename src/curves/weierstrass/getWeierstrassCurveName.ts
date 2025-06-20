import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { p256_CURVE } from './p256';
import { p384_CURVE } from './p384';
import { p521_CURVE } from './p521';
import { secp256k1_CURVE } from './secp256k1';

/**
 * Returns the name of the Weierstrass curve based on the provided curve function.
 *
 * @param {CurveFn} curve - The curve function containing the curve parameters.
 * @returns {string} The name of the Weierstrass curve.
 * @throws {Error} Throws an error if the curve is unknown.
 */
export const getWeierstrassCurveName = (curve: CurveFn): string => {
  switch (curve.CURVE.p) {
    case p256_CURVE.p:
      return 'P-256';
    case p384_CURVE.p:
      return 'P-384';
    case p521_CURVE.p:
      return 'P-521';
    case secp256k1_CURVE.p:
      return 'secp256k1';
    default:
      throw new Error('Unknown curve');
  }
};
