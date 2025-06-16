import { CurveFn } from '@noble/curves/abstract/edwards';
import { JwkPrivateKey } from '../../types';
import { ed25519IsValidPrivateKey } from './ed25519IsValidPrivateKey';
import { ed25519ToJwkPublicKey } from './ed25519ToJwkPublicKey';
import { encodeBase64Url } from 'u8a-utils';

/**
 * Converts an Ed25519 private key to a JWK (JSON Web Key) format.
 *
 * @param {CurveFn} curve - The curve function used to derive the public key from the private key.
 * @param {Uint8Array} privateKey - The private key as a Uint8Array.
 * @returns {JwkPrivateKey} The JWK representation of the private key.
 * @throws {Error} Throws an error if the private key is invalid.
 */
export const ed25519ToJwkPrivateKey = (
  curve: CurveFn,
  privateKey: Uint8Array,
): JwkPrivateKey => {
  if (!ed25519IsValidPrivateKey(curve, privateKey)) {
    throw new Error('Ed25519 private key is invalid');
  }

  const publicKey = curve.getPublicKey(privateKey);
  const jwkPublicKey = ed25519ToJwkPublicKey(curve, publicKey);
  const jwkPrivateKey: JwkPrivateKey = {
    ...jwkPublicKey,
    d: encodeBase64Url(privateKey),
  };

  return jwkPrivateKey;
};
