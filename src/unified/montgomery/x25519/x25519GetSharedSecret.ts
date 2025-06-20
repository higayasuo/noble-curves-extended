import { CurveFn } from '@noble/curves/abstract/montgomery';
import { x25519IsSmallOrderPoint } from './x25519IsSmallOrderPoint';
import type { GetSharedSecretParams } from '../../types';

/**
 * Computes the shared secret for the X25519 curve using a private key and a public key.
 *
 * @param {CurveFn} curve - The curve function used to compute the shared secret.
 * @param {GetSharedSecretParams} params - An object containing the private and public keys.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
 * @returns {Uint8Array} The computed shared secret as a Uint8Array.
 * @throws {Error} Throws an error if the private key or public key is invalid.
 */
export const x25519GetSharedSecret = (
  curve: CurveFn,
  { privateKey, publicKey }: GetSharedSecretParams,
): Uint8Array => {
  try {
    if (x25519IsSmallOrderPoint(publicKey)) {
      throw new Error('Public key is a small order point');
    }

    const sharedSecret = curve.getSharedSecret(privateKey, publicKey);

    if (sharedSecret.some((byte) => byte !== 0)) {
      return sharedSecret;
    }

    throw new Error('Shared secret is zero');
  } catch (error) {
    console.error(error);
    throw new Error('Failed to compute shared secret');
  }
};
