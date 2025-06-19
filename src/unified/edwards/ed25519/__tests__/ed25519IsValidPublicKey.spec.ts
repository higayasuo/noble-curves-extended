import { describe, it, expect } from 'vitest';
import { ed25519IsValidPublicKey } from '../ed25519IsValidPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { decodeHex } from 'u8a-utils';

describe('ed25519IsValidPublicKey', () => {
  it('should return true for a valid public key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    expect(ed25519IsValidPublicKey(curve, publicKey)).toBe(true);
  });

  it('should return false for an invalid public key (wrong length)', () => {
    const curve = createEd25519(randomBytes);
    const invalidPublicKey = new Uint8Array(16); // Too short
    expect(ed25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });

  it('should return false for an invalid public key (all zeros)', () => {
    const curve = createEd25519(randomBytes);
    const invalidPublicKey = new Uint8Array(32).fill(0);
    expect(ed25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });

  it('should return false for an invalid public key (invalid y-coordinate)', () => {
    const curve = createEd25519(randomBytes);
    // This is a point with an invalid y-coordinate (not on the curve)
    const invalidPublicKey = decodeHex(
      '0000000000000000000000000000000000000000000000000000000000000001',
    );
    expect(ed25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });

  it('should return false for an invalid public key (invalid x-coordinate)', () => {
    const curve = createEd25519(randomBytes);
    // This is a point with an invalid x-coordinate (not on the curve)
    const invalidPublicKey = decodeHex(
      '0100000000000000000000000000000000000000000000000000000000000000',
    );
    expect(ed25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });
});
