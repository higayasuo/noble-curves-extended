import { CurveFn } from '@noble/curves/abstract/montgomery';

/**
 * Validates if a given private key is valid for the x25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to validate the private key.
 * @param {Uint8Array} privateKey - The private key to validate.
 * @returns {boolean} True if the private key is valid, false otherwise.
 */
export const x25519IsValidPrivateKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
): boolean => {
  if (privateKey.length !== 32) {
    return false;
  }

  // RFC 7748 §5
  const [first, last] = [privateKey[0], privateKey[31]];

  if ((first & 248) !== first || (last & 192) !== 64) {
    return false;
  }

  try {
    curve.getPublicKey(privateKey);
    return true;
  } catch {
    return false;
  }
};
