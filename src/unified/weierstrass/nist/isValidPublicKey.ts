import { CurveFn } from '@noble/curves/abstract/weierstrass';

/**
 * Parameters for validating a public key.
 */
export type IsValidPublicKeyParams = {
  curve: CurveFn;
  publicKey: Uint8Array;
};

/**
 * Validates a public key by checking if it can be represented as a valid point on the given curve.
 *
 * @param {IsValidPublicKeyParams} params - The parameters including the curve and the public key to validate.
 * @returns {boolean} - Returns true if the public key is valid, otherwise false.
 */
export const isValidPublicKey = ({
  curve,
  publicKey,
}: IsValidPublicKeyParams): boolean => {
  try {
    const point = curve.ProjectivePoint.fromHex(publicKey);
    point.assertValidity();

    return true;
  } catch (error) {
    console.log(error);
    return false;
  }
};
