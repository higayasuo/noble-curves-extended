import { describe, it, expect } from 'vitest';
import { getEdwardsCurveName } from '../getEdwardsCurveName';
import { createEd25519 } from '../ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('getEdwardsCurveName', () => {
  it('should return Ed25519 for ed25519 curve', () => {
    const curve = createEd25519(randomBytes);
    const curveName = getEdwardsCurveName(curve);

    expect(curveName).toBe('Ed25519');
  });

  it('should throw error for unknown curve', () => {
    const unknownCurve = {
      CURVE: {
        p: BigInt('0x1234567890abcdef'), // Unknown prime
      },
    } as any;

    expect(() => getEdwardsCurveName(unknownCurve)).toThrow('Unknown curve');
  });
});
