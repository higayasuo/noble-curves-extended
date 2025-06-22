import { describe, it, expect } from 'vitest';
import { getWeierstrassSignatureAlgorithm } from '../getWeierstrassSignatureAlgorithm';
import { createP256 } from '../p256';
import { createP384 } from '../p384';
import { createP521 } from '../p521';
import { createSecp256k1 } from '../secp256k1';
import { randomBytes } from '@noble/hashes/utils';

describe('getWeierstrassSignatureAlgorithm', () => {
  describe('valid curves', () => {
    it('should return ES256 for P-256 curve', () => {
      const p256 = createP256(randomBytes);
      expect(getWeierstrassSignatureAlgorithm(p256)).toBe('ES256');
    });

    it('should return ES384 for P-384 curve', () => {
      const p384 = createP384(randomBytes);
      expect(getWeierstrassSignatureAlgorithm(p384)).toBe('ES384');
    });

    it('should return ES512 for P-521 curve', () => {
      const p521 = createP521(randomBytes);
      expect(getWeierstrassSignatureAlgorithm(p521)).toBe('ES512');
    });

    it('should return ES256K for secp256k1 curve', () => {
      const secp256k1 = createSecp256k1(randomBytes);
      expect(getWeierstrassSignatureAlgorithm(secp256k1)).toBe('ES256K');
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

      expect(() => getWeierstrassSignatureAlgorithm(mockCurve)).toThrow(
        'Unknown curve',
      );
    });
  });

  describe('signature algorithm uniqueness', () => {
    it('should have unique signature algorithms for all four curves', () => {
      const p256 = createP256(randomBytes);
      const p384 = createP384(randomBytes);
      const p521 = createP521(randomBytes);
      const secp256k1 = createSecp256k1(randomBytes);

      const algorithms = new Set([
        getWeierstrassSignatureAlgorithm(p256),
        getWeierstrassSignatureAlgorithm(p384),
        getWeierstrassSignatureAlgorithm(p521),
        getWeierstrassSignatureAlgorithm(secp256k1),
      ]);

      expect(algorithms.size).toBe(4);
    });
  });
});
