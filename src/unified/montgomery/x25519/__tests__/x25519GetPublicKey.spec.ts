import { describe, expect, it, vi } from 'vitest';
import { x25519GetPublicKey } from '../x25519GetPublicKey';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';

describe('x25519GetPublicKey', () => {
  it('should generate a valid public key from a valid private key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = x25519GetPublicKey(curve, privateKey);
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
  });

  it('should throw an error for uncompressed public keys', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    expect(() => x25519GetPublicKey(curve, privateKey, false)).toThrow(
      'Uncompressed public key is not supported',
    );
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createX25519(randomBytes);
    const privateKey = new Uint8Array(31);
    expect(() => x25519GetPublicKey(curve, privateKey)).toThrow(
      'Private key is invalid',
    );
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = new Uint8Array(32);
    expect(() => x25519GetPublicKey(curve, privateKey)).toThrow(
      'Private key is invalid',
    );
  });

  it('should generate different public keys for different private keys', () => {
    const curve = createX25519(randomBytes);
    const privateKey1 = curve.utils.randomPrivateKey();
    const privateKey2 = curve.utils.randomPrivateKey();

    const publicKey1 = x25519GetPublicKey(curve, privateKey1);
    const publicKey2 = x25519GetPublicKey(curve, privateKey2);

    expect(publicKey1).not.toEqual(publicKey2);
  });

  it('should throw a generic error when curve.getPublicKey throws an error', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();

    // Mock the curve.getPublicKey to throw an error only when called from the main function
    const originalGetPublicKey = curve.getPublicKey;
    let callCount = 0;
    curve.getPublicKey = vi.fn().mockImplementation((key: Uint8Array) => {
      callCount++;
      // The first call is from x25519IsValidPrivateKey, the second is from x25519GetPublicKey
      if (callCount === 2) {
        throw new Error('Internal curve error');
      }
      return originalGetPublicKey.call(curve, key);
    });

    expect(() => x25519GetPublicKey(curve, privateKey)).toThrow(
      'Failed to get public key',
    );

    // Restore the original method
    curve.getPublicKey = originalGetPublicKey;
  });
});
