import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519_CURVE } from './ed25519';
import { EdwardsCurveName } from './types';

/**
 * Returns the name of the edwards curve based on the provided curve function.
 *
 * @param {CurveFn} curve - The curve function containing the curve parameters.
 * @returns {EdwardsCurveName} The name of the edwards curve.
 * @throws {Error} Throws an error if the curve is unknown.
 */
export const getEdwardsCurveName = (curve: CurveFn): EdwardsCurveName => {
  switch (curve.CURVE.p) {
    case ed25519_CURVE.p:
      return 'Ed25519';
    default:
      throw new Error('Unknown curve');
  }
};
