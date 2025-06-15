import { describe, it, expect } from 'vitest';
import { x25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { x25519GetSharedSecret } from '../x25519GetSharedSecret';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519GetSharedSecret', () => {
  it('should compute the same shared secret for both parties', () => {
    const curve = x25519(randomBytes);
    const alicePrivateKey = curve.utils.randomPrivateKey();
    const alicePublicKey = curve.getPublicKey(alicePrivateKey);
    const bobPrivateKey = curve.utils.randomPrivateKey();
    const bobPublicKey = curve.getPublicKey(bobPrivateKey);

    const aliceSharedSecret = x25519GetSharedSecret(
      curve,
      alicePrivateKey,
      bobPublicKey,
    );
    const bobSharedSecret = x25519GetSharedSecret(
      curve,
      bobPrivateKey,
      alicePublicKey,
    );

    expect(aliceSharedSecret).toEqual(bobSharedSecret);
  });

  it('should throw an error for invalid private key', () => {
    const curve = x25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(32); // All zeros
    const publicKey = curve.getPublicKey(curve.utils.randomPrivateKey());

    expect(() =>
      x25519GetSharedSecret(curve, invalidPrivateKey, publicKey),
    ).toThrow('Invalid X25519 private key');
  });

  it('should throw an error for invalid public key', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const invalidPublicKey = new Uint8Array(32); // All zeros

    expect(() =>
      x25519GetSharedSecret(curve, privateKey, invalidPublicKey),
    ).toThrow('Invalid X25519 public key');
  });

  it('should throw an error for private key with wrong length', () => {
    const curve = x25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(31); // Wrong length
    const publicKey = curve.getPublicKey(curve.utils.randomPrivateKey());

    expect(() =>
      x25519GetSharedSecret(curve, invalidPrivateKey, publicKey),
    ).toThrow('Invalid X25519 private key');
  });

  it('should throw an error for public key with wrong length', () => {
    const curve = x25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const invalidPublicKey = new Uint8Array(31); // Wrong length

    expect(() =>
      x25519GetSharedSecret(curve, privateKey, invalidPublicKey),
    ).toThrow('Invalid X25519 public key');
  });
});
