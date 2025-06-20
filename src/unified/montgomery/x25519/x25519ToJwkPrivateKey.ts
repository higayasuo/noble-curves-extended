import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPrivateKey } from '../../types';
import { x25519ToJwkPublicKey } from './x25519ToJwkPublicKey';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts a raw X25519 private key to JWK format.
 *
 * @param {CurveFn} curve - The curve function used for conversion.
 * @param {Uint8Array} privateKey - The private key in raw format.
 * @returns {JwkPrivateKey} The private key in JWK format.
 * @throws {Error} Throws an error if the conversion fails.
 */
export const x25519ToJwkPrivateKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
): JwkPrivateKey => {
  try {
    const publicKey = curve.getPublicKey(privateKey);
    const jwkPublicKey = x25519ToJwkPublicKey(curve, publicKey);
    const jwkPrivateKey: JwkPrivateKey = {
      ...jwkPublicKey,
      d: encodeBase64Url(privateKey),
    };

    return jwkPrivateKey;
  } catch (error) {
    console.error(error);
    throw new Error('Failed to convert private key to JWK');
  }
};
