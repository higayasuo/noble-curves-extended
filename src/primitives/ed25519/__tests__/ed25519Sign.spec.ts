import { describe, it, expect } from 'vitest';
import { ed25519Sign } from '../ed25519Sign';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

const message = new TextEncoder().encode('hello');

describe('ed25519Sign', () => {
  it('should sign a message with a valid private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const signature = ed25519Sign(curve, { message, privateKey });
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(16); // Too short
    expect(() =>
      ed25519Sign(curve, { message, privateKey: invalidKey }),
    ).toThrow('Ed25519 private key is invalid');
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(32); // All zeros
    expect(() =>
      ed25519Sign(curve, { message, privateKey: invalidKey }),
    ).toThrow('Ed25519 private key is invalid');
  });

  it('should produce a signature that can be verified by Web Crypto API', async () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const signature = ed25519Sign(curve, { message, privateKey });

    // Import the public key into Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );

    // Verify the signature
    const isValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      signature,
      message,
    );

    expect(isValid).toBe(true);
  });
});
