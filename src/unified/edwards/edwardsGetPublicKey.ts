import { CurveFn } from '@noble/curves/abstract/edwards';
import { compareUint8Arrays } from 'u8a-utils';

/**
 * Derives a public key from a private key using the edwards curve.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @param {boolean} [compressed=true] - Indicates if the public key should be compressed.
 * @returns {Uint8Array} The derived public key.
 * @throws {Error} Throws an error if the public key cannot be derived or if the embedded public key is invalid.
 */
export const edwardsGetPublicKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
  compressed = true,
): Uint8Array => {
  if (!compressed) {
    throw new Error('Uncompressed public key is not supported');
  }

  try {
    const keyByteLength = curve.CURVE.nByteLength;
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
    console.error(error);
    throw new Error('Failed to get public key');
  }
};
