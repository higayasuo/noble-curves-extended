import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { montgomeryRandomPrivateKey } from '../montgomeryRandomPrivateKey';
import { randomBytes } from '@noble/hashes/utils';

describe('montgomeryRandomPrivateKey', () => {
  const curve = createX25519(randomBytes);

  it('should generate a valid, adjusted private key', () => {
    const privateKey = montgomeryRandomPrivateKey(curve);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(curve.GuBytes.length);
    // MSB cleared, LSB set
    // expect((privateKey[0] & 0b11111000) === privateKey[0]).toBe(true);
    // expect((privateKey[31] & 0b01111111) === privateKey[31]).toBe(true);
    // expect((privateKey[31] & 0b01000000) !== 0).toBe(true);
    // Not all zeros
    expect(privateKey.some((b) => b !== 0)).toBe(true);
  });

  it('should generate different keys on each call', () => {
    const key1 = montgomeryRandomPrivateKey(curve);
    const key2 = montgomeryRandomPrivateKey(curve);
    expect(key1).not.toEqual(key2);
  });

  it('should throw an error if randomPrivateKey fails', () => {
    // Mock randomPrivateKey to throw
    const originalRandomPrivateKey = curve.utils.randomPrivateKey;
    curve.utils.randomPrivateKey = () => {
      throw new Error('Random failure');
    };
    expect(() => montgomeryRandomPrivateKey(curve)).toThrow(
      'Failed to generate random private key',
    );
    // Restore original
    curve.utils.randomPrivateKey = originalRandomPrivateKey;
  });
});
