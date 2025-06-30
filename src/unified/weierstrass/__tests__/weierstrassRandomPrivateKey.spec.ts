import { describe, it, expect } from 'vitest';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { weierstrassRandomPrivateKey } from '../weierstrassRandomPrivateKey';
import { randomBytes } from '@noble/hashes/utils';

describe('weierstrassRandomPrivateKey', () => {
  const curves = [
    { name: 'P-256', createCurve: createP256, expectedLength: 32 },
    { name: 'P-384', createCurve: createP384, expectedLength: 48 },
    { name: 'P-521', createCurve: createP521, expectedLength: 66 },
    { name: 'secp256k1', createCurve: createSecp256k1, expectedLength: 32 },
  ];

  describe('normal cases', () => {
    it.each(curves)(
      'should generate a valid $name private key',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        expect(privateKey).toBeInstanceOf(Uint8Array);
        expect(privateKey.length).toBe(expectedLength);
        // Not all zeros
        expect(privateKey.some((b) => b !== 0)).toBe(true);
      },
    );

    it.each(curves)(
      'should generate different keys on each call for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const key1 = weierstrassRandomPrivateKey(curve);
        const key2 = weierstrassRandomPrivateKey(curve);
        expect(key1).not.toEqual(key2);
      },
    );

    it.each(curves)(
      'should generate valid private keys that can derive public keys for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        const publicKey = curve.getPublicKey(privateKey);
        expect(publicKey).toBeInstanceOf(Uint8Array);
        // All Weierstrass curves should generate compressed public keys
        expect(publicKey.length).toBe(privateKey.length + 1);
      },
    );
  });

  describe('exception cases', () => {
    it.each(curves)(
      'should throw an error when randomPrivateKey fails for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        // Mock the randomPrivateKey method to throw an error
        const originalRandomPrivateKey = curve.utils.randomPrivateKey;
        curve.utils.randomPrivateKey = () => {
          throw new Error('Mock error');
        };

        expect(() => weierstrassRandomPrivateKey(curve)).toThrow(
          'Failed to generate random private key',
        );

        // Restore the original method
        curve.utils.randomPrivateKey = originalRandomPrivateKey;
      },
    );
  });
});
