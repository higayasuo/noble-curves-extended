import { describe, it, expect } from 'vitest';
import { x25519IsValidPrivateKey } from '../x25519IsValidPrivateKey';
import { x25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519IsValidPrivateKey', () => {
  it('should return true for a valid private key', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    expect(x25519IsValidPrivateKey(curve, privateKey)).toBe(true);
  });

  it('should return false for an invalid private key (all zeros)', () => {
    const curve = x25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(32).fill(0);
    expect(x25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should return false for an invalid private key (wrong length)', () => {
    const curve = x25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(16); // Too short
    expect(x25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should return false for an invalid private key (all ones)', () => {
    const curve = x25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(32).fill(255);
    expect(x25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should return false for an invalid private key (invalid last byte)', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const invalidPrivateKey = new Uint8Array(privateKey);
    // Set last byte to an invalid value (not 64-127)
    invalidPrivateKey[31] = 0;
    expect(x25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should return false for a mutated valid private key', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const mutatedKey = new Uint8Array(privateKey);
    mutatedKey[0] ^= 0xff; // Flip all bits in the first byte
    expect(x25519IsValidPrivateKey(curve, mutatedKey)).toBe(false);
  });

  it('should check randomPrivateKey implementation', () => {
    const curve = x25519(randomBytes);
    //const curve = x25519Original;
    const privateKey = curve.utils.randomPrivateKey();

    // Check length
    expect(privateKey.length).toBe(32);

    // Check first byte (lower 3 bits should be 0)
    expect(privateKey[0] & 0b00000111).toBe(0);

    // Check last byte (upper 2 bits should be 01)
    expect((privateKey[31] & 0b11000000) >>> 6).toBe(0b01);
  });
});
