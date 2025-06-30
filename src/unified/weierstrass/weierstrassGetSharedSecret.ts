import { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { GetSharedSecretParams } from '../types';
import { getErrorMessage } from '@/utils/getErrorMessage';

/**
 * Computes the shared secret for the Weierstrass curve using a private key and a public key.
 *
 * @param {CurveFn} curve - The curve function used to compute the shared secret.
 * @param {GetSharedSecretParams} params - An object containing the private and public keys.
 * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
 * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
 * @returns {Uint8Array} The computed shared secret as a Uint8Array.
 * @throws {Error} Throws an error if the private key or public key is invalid.
 */
export const weierstrassGetSharedSecret = (
  curve: CurveFn,
  { privateKey, publicKey }: GetSharedSecretParams,
): Uint8Array => {
  try {
    const sharedSecret = curve.getSharedSecret(privateKey, publicKey).slice(1);

    if (sharedSecret.some((byte) => byte !== 0)) {
      return sharedSecret;
    }

    throw new Error('Shared secret is zero');
  } catch (error) {
    console.log(getErrorMessage(error));
    throw new Error('Failed to compute shared secret');
  }
};
