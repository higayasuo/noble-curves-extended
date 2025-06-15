import { describe, it, expect } from 'vitest';
import { x25519 } from '../x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519', () => {
  it('should generate matching shared secrets between two key pairs', () => {
    const curve = x25519(randomBytes);

    // Generate two key pairs
    const alicePrivateKey = curve.utils.randomPrivateKey();
    const alicePublicKey = curve.getPublicKey(alicePrivateKey);

    const bobPrivateKey = curve.utils.randomPrivateKey();
    const bobPublicKey = curve.getPublicKey(bobPrivateKey);

    // Calculate shared secrets
    const aliceSharedSecret = curve.getSharedSecret(
      alicePrivateKey,
      bobPublicKey,
    );
    const bobSharedSecret = curve.getSharedSecret(
      bobPrivateKey,
      alicePublicKey,
    );

    // Verify that both shared secrets are identical
    expect(aliceSharedSecret).toEqual(bobSharedSecret);
  });

  it('should generate private keys with correct bit patterns after adjustScalarBytes', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();

    // Check length
    expect(privateKey.length).toBe(32);

    // Check first byte (lower 3 bits should be 0)
    expect(privateKey[0] & 0b00000111).toBe(0);

    // Check last byte (upper 2 bits should be 01)
    expect((privateKey[31] & 0b11000000) >>> 6).toBe(0b01);
  });
});
