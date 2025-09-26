import { CurveFn } from '@noble/curves/abstract/edwards';
import { getErrorMessage } from '@/utils/getErrorMessage';
import { compareUint8Arrays } from 'u8a-utils';

/**
 * Derives a public key from a private key using the edwards curve.
 * Accepts either:
 * - a raw seed of length `keyByteLength`, or
 * - a concatenation of `seed || embeddedPublicKey` of length `keyByteLength * 2`.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key.
 * @param {number} keyByteLength - The base key byte length (seed length, without embedded public key).
 * @param {Uint8Array} privateKey - Private key as Uint8Array of length `keyByteLength` or `keyByteLength * 2` (seed || embeddedPublicKey).
 * @param {boolean} [compressed=true] - Indicates if the public key should be compressed.
 * @returns {Uint8Array} The derived public key.
 * @throws {Error} Throws an error if `compressed` is false, if the embedded public key is invalid, or if derivation fails.
 */
export const edwardsGetPublicKey = (
  curve: CurveFn,
  keyByteLength: number,
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array => {
  if (!compressed) {
    throw new Error('Uncompressed public key is not supported');
  }

  try {
    if (privateKey.length === keyByteLength * 2) {
      const seed = privateKey.slice(0, keyByteLength);
      const embeddedPublicKey = privateKey.slice(keyByteLength);
      const publicKey = curve.getPublicKey(seed);

      if (compareUint8Arrays(publicKey, embeddedPublicKey)) {
        return publicKey;
      }

      throw new Error('Embedded public key is invalid');
    }

    return curve.getPublicKey(privateKey);
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to get public key');
  }
};
