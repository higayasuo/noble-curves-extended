import { describe, expect, it } from 'vitest';
import { ed25519GetPublicKey } from '../ed25519GetPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

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
      'Uncompressed public key is not supported',
    );
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = new Uint8Array(31);
    expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
      'Private key is invalid',
    );
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = new Uint8Array(32);
    expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
      'Private key is invalid',
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
