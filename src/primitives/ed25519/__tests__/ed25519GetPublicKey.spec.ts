import { describe, expect, it } from 'vitest';
import { ed25519GetPublicKey } from '../ed25519GetPublicKey';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('ed25519GetPublicKey', () => {
  it('should generate a valid public key from a valid private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = ed25519GetPublicKey(curve, privateKey);
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
  });

  it('should throw an error for uncompressed public keys', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    expect(() => ed25519GetPublicKey(curve, privateKey, false)).toThrow(
      'Ed25519 does not support uncompressed public keys',
    );
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = new Uint8Array(31);
    expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
      'Ed25519 private key is invalid',
    );
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = new Uint8Array(32);
    expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
      'Ed25519 private key is invalid',
    );
  });

  it('should generate different public keys for different private keys', () => {
    const curve = createEd25519(randomBytes);
    const privateKey1 = curve.utils.randomPrivateKey();
    const privateKey2 = curve.utils.randomPrivateKey();

    const publicKey1 = ed25519GetPublicKey(curve, privateKey1);
    const publicKey2 = ed25519GetPublicKey(curve, privateKey2);

    expect(publicKey1).not.toEqual(publicKey2);
  });
});
