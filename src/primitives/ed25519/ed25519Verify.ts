import { CurveFn } from '@noble/curves/abstract/edwards';
import { ed25519IsValidPublicKey } from './ed25519IsValidPublicKey';

export const ed25519Verify = (
  curve: CurveFn,
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean => {
  if (!ed25519IsValidPublicKey(curve, publicKey)) {
    throw new Error('Ed25519 public key is invalid');
  }

  return curve.verify(signature, message, publicKey);
};
