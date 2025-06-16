import { describe, it, expect } from 'vitest';
import { x25519RandomPrivateKey } from '../x25519RandomPrivateKey';
import { createX25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519RandomPrivateKey', () => {
  it('should generate a valid private key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = x25519RandomPrivateKey(curve);

    // Check that the private key is a Uint8Array
    expect(privateKey).toBeInstanceOf(Uint8Array);

    // Check that the private key has the correct length (32 bytes for x25519)
    expect(privateKey.length).toBe(32);
  });

  it('should generate different private keys on each call', () => {
    const curve = createX25519(randomBytes);
    const privateKey1 = x25519RandomPrivateKey(curve);
    const privateKey2 = x25519RandomPrivateKey(curve);

    // Check that the private keys are different
    expect(privateKey1).not.toEqual(privateKey2);
  });
});
