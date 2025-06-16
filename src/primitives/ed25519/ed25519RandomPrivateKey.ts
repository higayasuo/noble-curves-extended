import { CurveFn } from '@noble/curves/abstract/edwards';
import { adjustScalarBytes } from '../../ed25519/ed25519';
import { sha512 } from '@noble/hashes/sha2';

/**
 * Generates a random private key for the ed25519 curve.
 * Following RFC 8032:
 * 1. Generate 32 random bytes
 * 2. Hash them with SHA-512
 * 3. Take first 32 bytes
 * 4. Adjust scalar bytes according to RFC 7748 §5
 *
 * @param {CurveFn} curve - The curve function used to generate the private key.
 * @returns {Uint8Array} A randomly generated private key.
 */
export const ed25519RandomPrivateKey = (curve: CurveFn): Uint8Array => {
  const edRaw = curve.utils.randomPrivateKey();
  const edHash = sha512(edRaw);
  const edAdjusted = adjustScalarBytes(edHash.slice(0, 32));
  return edAdjusted;
};
