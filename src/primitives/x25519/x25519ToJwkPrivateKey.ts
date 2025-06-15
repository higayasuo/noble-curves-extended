import { CurveFn } from '@noble/curves/abstract/montgomery';
import { JwkPrivateKey } from '../../types';
import { x25519IsValidPrivateKey } from './x25519IsValidPrivateKey';
import { x25519ToJwkPublicKey } from './x25519ToJwkPublicKey';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts an x25519 private key to a JWK (JSON Web Key) format.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key from the private key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @returns {JwkPrivateKey} The JWK representation of the private key.
 * @throws {Error} Throws an error if the private key is invalid.
 */
export const x25519ToJwkPrivateKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
): JwkPrivateKey => {
  if (!x25519IsValidPrivateKey(curve, privateKey)) {
    throw new Error(
      'Invalid X25519 private key: key must be 32 bytes and satisfy the X25519 key requirements',
    );
  }

  const publicKey = curve.getPublicKey(privateKey);
  const jwkPublicKey = x25519ToJwkPublicKey(curve, publicKey);
  const jwkPrivateKey: JwkPrivateKey = {
    ...jwkPublicKey,
    d: encodeBase64Url(privateKey),
  };

  return jwkPrivateKey;
};
