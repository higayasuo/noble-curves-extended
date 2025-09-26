import { CurveFn } from '@noble/curves/abstract/edwards';

/**
 * Gets the key byte length for an Edwards curve.
 *
 * @param {CurveFn} curve - The Edwards curve function.
 * @returns {number} The key byte length, preferring nByteLength if available, otherwise using Fp.BYTES.
 */
export const getEdwardsKeyByteLength = (curve: CurveFn): number => {
  return curve.CURVE.nByteLength ?? curve.CURVE.Fp.BYTES;
};
