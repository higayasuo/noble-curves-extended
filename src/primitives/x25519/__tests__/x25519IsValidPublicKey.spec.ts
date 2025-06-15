import { describe, it, expect } from 'vitest';
import { x25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { x25519IsValidPublicKey } from '../x25519IsValidPublicKey';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519IsValidPublicKey', () => {
  it('should return true for a valid public key', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    expect(x25519IsValidPublicKey(curve, publicKey)).toBe(true);
  });

  it('should return false for an invalid public key (wrong length)', () => {
    const curve = x25519(randomBytes);
    const invalidPublicKey = new Uint8Array(16); // Too short
    expect(x25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });

  it('should return false for an invalid public key (all zeros)', () => {
    const curve = x25519(randomBytes);
    const invalidPublicKey = new Uint8Array(32).fill(0);
    expect(x25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });
});
