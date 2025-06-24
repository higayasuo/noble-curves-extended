import { describe, it, expect } from 'vitest';
import { getMontgomeryCurveName } from '../getMontgomeryCurveName';
import { createX25519 } from '../x25519';
import { randomBytes } from '@noble/hashes/utils';

describe('getMontgomeryCurveName', () => {
  it('should return X25519 for x25519 curve', () => {
    const curve = createX25519(randomBytes);
    const curveName = getMontgomeryCurveName(curve);

    expect(curveName).toBe('X25519');
  });

  it('should throw error for unknown curve', () => {
    const unknownCurve = {
      GuBytes: new Uint8Array(48), // Unknown length
    } as any;

    expect(() => getMontgomeryCurveName(unknownCurve)).toThrow('Unknown curve');
  });

  it('should verify GuBytes length for X25519', () => {
    const curve = createX25519(randomBytes);

    expect(curve.GuBytes.length).toBe(32);
  });
});
