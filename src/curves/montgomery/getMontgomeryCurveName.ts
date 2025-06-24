import { CurveFn } from '@noble/curves/abstract/montgomery';
import { MontgomeryCurveName } from './types';

/**
 * Returns the name of the montgomery curve based on the provided curve function.
 *
 * @param {CurveFn} curve - The curve function containing the curve parameters.
 * @returns {MontgomeryCurveName} The name of the montgomery curve.
 * @throws {Error} Throws an error if the curve is unknown.
 */
export const getMontgomeryCurveName = (curve: CurveFn): MontgomeryCurveName => {
  switch (curve.GuBytes.length) {
    case 32:
      return 'X25519';
    // case 56:
    //   return 'X448';
    default:
      throw new Error('Unknown curve');
  }
};
