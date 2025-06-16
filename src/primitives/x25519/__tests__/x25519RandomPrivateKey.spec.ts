import { describe, it, expect } from 'vitest';
import { createX25519 } from '../../../x25519/x25519';
import { x25519RandomPrivateKey } from '../x25519RandomPrivateKey';
import { adjustScalarBytes } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519RandomPrivateKey', () => {
  it('should generate a valid, adjusted private key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = x25519RandomPrivateKey(curve);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
    // MSB cleared, LSB set
    expect((privateKey[0] & 0b11111000) === privateKey[0]).toBe(true);
    expect((privateKey[31] & 0b01111111) === privateKey[31]).toBe(true);
    expect((privateKey[31] & 0b01000000) !== 0).toBe(true);
    // Not all zeros
    expect(privateKey.some((b) => b !== 0)).toBe(true);
  });

  it('should generate different keys on each call', () => {
    const curve = createX25519(randomBytes);
    const key1 = x25519RandomPrivateKey(curve);
    const key2 = x25519RandomPrivateKey(curve);
    expect(key1).not.toEqual(key2);
  });
});
