import { describe, it, expect } from 'vitest';
import {
  x25519IsSmallOrderPoint,
  SMALL_ORDER_POINTS,
} from '../x25519IsSmallOrderPoint';
import { decodeHex } from 'u8a-utils';

describe('x25519IsSmallOrderPoint', () => {
  describe('small order points (should return true)', () => {
    it('should return true for 0 (order 1)', () => {
      const publicKey = decodeHex(
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for 1 (order 1)', () => {
      const publicKey = decodeHex(
        '0100000000000000000000000000000000000000000000000000000000000000',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for point with order 8 (first)', () => {
      const publicKey = decodeHex(
        'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for point with order 8 (second)', () => {
      const publicKey = decodeHex(
        '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for p-1 (order 2)', () => {
      const publicKey = decodeHex(
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for p (order 4)', () => {
      const publicKey = decodeHex(
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for p+1 (order 1)', () => {
      const publicKey = decodeHex(
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(true);
    });

    it('should return true for all points in SMALL_ORDER_POINTS array', () => {
      SMALL_ORDER_POINTS.forEach((point) => {
        expect(x25519IsSmallOrderPoint(point)).toBe(true);
      });
    });
  });

  describe('non-small order points (should return false)', () => {
    it('should return false for a typical x25519 public key', () => {
      // Example of a typical x25519 public key (not a small order point)
      const publicKey = decodeHex(
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      );
      expect(x25519IsSmallOrderPoint(publicKey)).toBe(false);
    });
  });

  describe('SMALL_ORDER_POINTS constant', () => {
    it('should have exactly 7 small order points', () => {
      expect(SMALL_ORDER_POINTS).toHaveLength(7);
    });

    it('should contain all points as Uint8Array with length 32', () => {
      SMALL_ORDER_POINTS.forEach((point) => {
        expect(point).toBeInstanceOf(Uint8Array);
        expect(point.length).toBe(32);
      });
    });

    it('should not contain duplicate points', () => {
      const uniquePoints = new Set();
      SMALL_ORDER_POINTS.forEach((point) => {
        const hexString = Buffer.from(point).toString('hex');
        expect(uniquePoints.has(hexString)).toBe(false);
        uniquePoints.add(hexString);
      });
    });
  });
});
