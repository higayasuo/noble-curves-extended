import { describe, it, expect } from 'vitest';
import { createX25519 } from '../x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../types';
import { x25519 } from '@noble/curves/ed25519';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519', () => {
  it('should generate matching shared secrets between two key pairs', () => {
    const curve = createX25519(randomBytes);

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

  it('should produce the same shared secret as noble implementation', () => {
    // Our implementation
    const ourCurve = createX25519(randomBytes);
    const alicePriv = ourCurve.utils.randomPrivateKey();
    const alicePub = ourCurve.getPublicKey(alicePriv);
    const bobPriv = ourCurve.utils.randomPrivateKey();
    const bobPub = ourCurve.getPublicKey(bobPriv);
    const ourSecret = ourCurve.getSharedSecret(alicePriv, bobPub);

    // Noble implementation
    const nobleSecret = x25519.getSharedSecret(alicePriv, bobPub);

    // Verify that both shared secrets are identical
    expect(ourSecret).toEqual(nobleSecret);
  });
});
