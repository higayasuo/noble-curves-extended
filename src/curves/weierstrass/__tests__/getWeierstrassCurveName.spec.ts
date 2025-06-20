import { describe, it, expect } from 'vitest';
import { getWeierstrassCurveName } from '../getWeierstrassCurveName';
import { createP256 } from '../p256';
import { createP384 } from '../p384';
import { createP521 } from '../p521';
import { createSecp256k1 } from '../secp256k1';
import { randomBytes } from '@noble/hashes/utils';

describe('getWeierstrassCurveName', () => {
  describe('valid curves', () => {
    it('should return P-256 for P-256 curve', () => {
      const p256 = createP256(randomBytes);
      expect(getWeierstrassCurveName(p256)).toBe('P-256');
    });

    it('should return P-384 for P-384 curve', () => {
      const p384 = createP384(randomBytes);
      expect(getWeierstrassCurveName(p384)).toBe('P-384');
    });

    it('should return P-521 for P-521 curve', () => {
      const p521 = createP521(randomBytes);
      expect(getWeierstrassCurveName(p521)).toBe('P-521');
    });

    it('should return secp256k1 for secp256k1 curve', () => {
      const secp256k1 = createSecp256k1(randomBytes);
      expect(getWeierstrassCurveName(secp256k1)).toBe('secp256k1');
    });
  });

  describe('unknown curve', () => {
    it('should throw an error for unknown curve', () => {
      // Create a mock curve with an unknown prime
      const mockCurve = {
        CURVE: {
          p: BigInt('0x1234567890abcdef'), // Unknown prime
        },
      } as any;

      expect(() => getWeierstrassCurveName(mockCurve)).toThrow('Unknown curve');
    });
  });

  describe('curve prime uniqueness', () => {
    it('should have unique prime values for all four curves', () => {
      const p256 = createP256(randomBytes);
      const p384 = createP384(randomBytes);
      const p521 = createP521(randomBytes);
      const secp256k1 = createSecp256k1(randomBytes);

      const primes = new Set([
        p256.CURVE.p,
        p384.CURVE.p,
        p521.CURVE.p,
        secp256k1.CURVE.p,
      ]);

      expect(primes.size).toBe(4);
    });
  });
});
