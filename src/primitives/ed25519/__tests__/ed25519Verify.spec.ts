import { describe, it, expect } from 'vitest';
import { ed25519Verify } from '../ed25519Verify';
import { ed25519Sign } from '../ed25519Sign';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

const message = new TextEncoder().encode('hello');

describe('ed25519Verify', () => {
  it('should verify a valid signature', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const signature = ed25519Sign(curve, { message, privateKey });
    expect(ed25519Verify(curve, { signature, message, publicKey })).toBe(true);
  });

  it('should return false for an invalid signature', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const invalidSignature = new Uint8Array(64); // All zeros
    expect(
      ed25519Verify(curve, { signature: invalidSignature, message, publicKey }),
    ).toBe(false);
  });

  it('should throw an error for an invalid public key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = new Uint8Array(32); // All zeros (invalid)
    const signature = ed25519Sign(curve, { message, privateKey });
    expect(() =>
      ed25519Verify(curve, { signature, message, publicKey }),
    ).toThrow('Ed25519 public key is invalid');
  });
});
