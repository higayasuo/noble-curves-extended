import { describe, it, expect } from 'vitest';
import { ed25519RandomPrivateKey } from '../ed25519RandomPrivateKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('ed25519RandomPrivateKey', () => {
  it('should generate a valid private key with correct bit patterns', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = ed25519RandomPrivateKey(curve);

    // Check that the private key is a Uint8Array
    expect(privateKey).toBeInstanceOf(Uint8Array);

    // Check that the private key has the correct length (32 bytes for ed25519)
    expect(privateKey.length).toBe(32);

    // Check first byte (lower 3 bits should be 0)
    expect(privateKey[0] & 0b00000111).toBe(0);

    // Check last byte (upper 2 bits should be 01)
    expect((privateKey[31] & 0b11000000) >>> 6).toBe(0b01);
  });

  it('should generate different private keys on each call', () => {
    const curve = createEd25519(randomBytes);
    const privateKey1 = ed25519RandomPrivateKey(curve);
    const privateKey2 = ed25519RandomPrivateKey(curve);

    // Check that the private keys are different
    expect(privateKey1).not.toEqual(privateKey2);
  });
});
