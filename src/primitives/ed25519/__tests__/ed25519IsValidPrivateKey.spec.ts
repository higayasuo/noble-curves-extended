import { describe, it, expect } from 'vitest';
import { ed25519IsValidPrivateKey } from '../ed25519IsValidPrivateKey';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('ed25519IsValidPrivateKey', () => {
  it('should return true for a valid private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    expect(ed25519IsValidPrivateKey(curve, privateKey)).toBe(true);
  });

  it('should return false for an invalid private key (all zeros)', () => {
    const curve = createEd25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(32).fill(0);
    expect(ed25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should return false for an invalid private key (wrong length)', () => {
    const curve = createEd25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(16); // Too short
    expect(ed25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });
});
