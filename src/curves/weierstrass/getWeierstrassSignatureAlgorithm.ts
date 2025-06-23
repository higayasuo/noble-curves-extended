import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { p256_CURVE } from './p256';
import { p384_CURVE } from './p384';
import { p521_CURVE } from './p521';
import { secp256k1_CURVE } from './secp256k1';
import { WeierstrassSignatureAlgorithmName } from './types';

/**
 * Returns the signature algorithm of the Weierstrass curve based on the provided curve function.
 *
 * @param {CurveFn} curve - The curve function containing the curve parameters.
 * @returns {WeierstrassSignatureAlgorithmName} The signature algorithm of the Weierstrass curve.
 * @throws {Error} Throws an error if the curve is unknown.
 */
export const getWeierstrassSignatureAlgorithm = (
  curve: CurveFn,
): WeierstrassSignatureAlgorithmName => {
  switch (curve.CURVE.p) {
    case p256_CURVE.p:
      return 'ES256';
    case p384_CURVE.p:
      return 'ES384';
    case p521_CURVE.p:
      return 'ES512';
    case secp256k1_CURVE.p:
      return 'ES256K';
    default:
      throw new Error('Unknown curve');
  }
};
