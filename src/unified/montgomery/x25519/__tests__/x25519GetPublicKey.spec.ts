import { describe, expect, it } from 'vitest';
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
      'x25519 does not support uncompressed public keys',
    );
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createX25519(randomBytes);
    const privateKey = new Uint8Array(31);
    expect(() => x25519GetPublicKey(curve, privateKey)).toThrow(
      'X25519 private key is invalid',
    );
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = new Uint8Array(32);
    expect(() => x25519GetPublicKey(curve, privateKey)).toThrow(
      'X25519 private key is invalid',
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
});
