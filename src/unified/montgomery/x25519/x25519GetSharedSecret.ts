import { CurveFn } from '@noble/curves/abstract/montgomery';
import { x25519IsValidPrivateKey } from './x25519IsValidPrivateKey';
import { x25519IsValidPublicKey } from './x25519IsValidPublicKey';
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
  // if (!x25519IsValidPrivateKey(curve, privateKey)) {
  //   throw new Error('Private key is invalid');
  // }

  if (!x25519IsValidPublicKey(curve, publicKey)) {
    throw new Error('Public key is invalid');
  }

  try {
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
