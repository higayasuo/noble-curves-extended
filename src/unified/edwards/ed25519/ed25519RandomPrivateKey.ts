import { CurveFn } from '@noble/curves/abstract/edwards';
import { sha512 } from '@noble/hashes/sha2';
import { adjustScalarBytes } from '@/curves/edwards/ed25519';

/**
 * Generates a random private key for the Ed25519 curve.
 *
 * This function uses a random seed, hashes it with SHA-512, and then adjusts
 * the scalar bytes to ensure compliance with Ed25519 requirements.
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated and adjusted private key.
 */
export const ed25519RandomPrivateKey = (curve: CurveFn): Uint8Array => {
  const seed = curve.utils.randomPrivateKey();
  const hash = sha512(seed);
  return adjustScalarBytes(hash.slice(0, 32));
};
