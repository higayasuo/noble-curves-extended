import { CurveFn } from '@noble/curves/abstract/montgomery';

/**
 * Validates if a given public key is valid for the x25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {Uint8Array} publicKey - The public key to validate.
 * @returns {boolean} True if the public key is valid, false otherwise.
 */
export const x25519IsValidPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): boolean => {
  if (publicKey.length !== 32) {
    return false;
  }

  // RFC 7748 §6.1
  try {
    const dummyPrivate = curve.utils.randomPrivateKey();
    const sharedSecret = curve.getSharedSecret(dummyPrivate, publicKey);
    return !sharedSecret.every((byte) => byte === 0);
  } catch {
    return false;
  }
};
