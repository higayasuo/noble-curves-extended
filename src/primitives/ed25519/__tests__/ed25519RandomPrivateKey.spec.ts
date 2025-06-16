import { describe, it, expect } from 'vitest';
import { ed25519RandomPrivateKey } from '../ed25519RandomPrivateKey';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('ed25519RandomPrivateKey', () => {
  it('should generate a valid private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = ed25519RandomPrivateKey(curve);

    // Check that the private key is a Uint8Array
    expect(privateKey).toBeInstanceOf(Uint8Array);

    // Check that the private key has the correct length (32 bytes for ed25519)
    expect(privateKey.length).toBe(32);
  });

  it('should generate different private keys on each call', () => {
    const curve = createEd25519(randomBytes);
    const privateKey1 = ed25519RandomPrivateKey(curve);
    const privateKey2 = ed25519RandomPrivateKey(curve);

    // Check that the private keys are different
    expect(privateKey1).not.toEqual(privateKey2);
  });
});
