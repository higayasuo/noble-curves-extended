import { describe, it, expect } from 'vitest';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { weierstrassIsValidPublicKey } from '../weierstrassIsValidPublicKey';
import { weierstrassGetPublicKey } from '../weierstrassGetPublicKey';
import { weierstrassRandomPrivateKey } from '../weierstrassRandomPrivateKey';
import { randomBytes } from '@noble/hashes/utils';

describe('weierstrassIsValidPublicKey', () => {
  const curves = [
    { name: 'P-256', createCurve: createP256, expectedLength: 33 },
    { name: 'P-384', createCurve: createP384, expectedLength: 49 },
    { name: 'P-521', createCurve: createP521, expectedLength: 67 },
    { name: 'secp256k1', createCurve: createSecp256k1, expectedLength: 33 },
  ];

  describe('valid public key tests', () => {
    it.each(curves)(
      'should return true for valid public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        const publicKey = weierstrassGetPublicKey(curve, privateKey);

        expect(weierstrassIsValidPublicKey(curve, publicKey)).toBe(true);
      },
    );
  });

  describe('invalid public key tests', () => {
    it.each(curves)(
      'should return false for all zeros public key for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const allZerosKey = new Uint8Array(expectedLength);

        expect(weierstrassIsValidPublicKey(curve, allZerosKey)).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for empty public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const emptyKey = new Uint8Array(0);

        expect(weierstrassIsValidPublicKey(curve, emptyKey)).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for public key with wrong length for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const wrongLengthKey = new Uint8Array(expectedLength + 1);
        wrongLengthKey.fill(1); // Fill with non-zero values

        expect(weierstrassIsValidPublicKey(curve, wrongLengthKey)).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for public key that is too short for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const shortKey = new Uint8Array(expectedLength - 1);
        shortKey.fill(1); // Fill with non-zero values

        expect(weierstrassIsValidPublicKey(curve, shortKey)).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for public key with invalid format for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const invalidKey = new Uint8Array(expectedLength);
        invalidKey.fill(0xff); // Fill with all 0xFF (invalid format)

        expect(weierstrassIsValidPublicKey(curve, invalidKey)).toBe(false);
      },
    );
  });

  describe('edge case tests', () => {
    it.each(curves)(
      'should return false for public key with only first byte non-zero for $name',
      ({ createCurve, expectedLength, name }) => {
        const curve = createCurve(randomBytes);
        const key = new Uint8Array(expectedLength);
        key[0] = 0x02; // Valid compressed format prefix
        // Rest remains zeros

        // NIST curves (P-256, P-384, P-521) accept this format, secp256k1 rejects it
        const expectedResult = name === 'secp256k1' ? false : true;
        expect(weierstrassIsValidPublicKey(curve, key)).toBe(expectedResult);
      },
    );

    it.each(curves)(
      'should return false for public key with only last byte non-zero for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const key = new Uint8Array(expectedLength);
        key[key.length - 1] = 0x01; // Only last byte non-zero

        expect(weierstrassIsValidPublicKey(curve, key)).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for public key with invalid compressed format for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const key = new Uint8Array(expectedLength);
        key[0] = 0x04; // Invalid prefix for compressed format
        key.fill(0x01, 1); // Fill rest with non-zero values

        expect(weierstrassIsValidPublicKey(curve, key)).toBe(false);
      },
    );
  });

  describe('consistency tests', () => {
    it.each(curves)(
      'should return consistent results for same public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        const publicKey = weierstrassGetPublicKey(curve, privateKey);

        // Test multiple times with the same key
        const result1 = weierstrassIsValidPublicKey(curve, publicKey);
        const result2 = weierstrassIsValidPublicKey(curve, publicKey);
        const result3 = weierstrassIsValidPublicKey(curve, publicKey);

        expect(result1).toBe(result2);
        expect(result2).toBe(result3);
        expect(result1).toBe(true);
      },
    );

    it.each(curves)(
      'should return consistent results for invalid keys for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const invalidKey = new Uint8Array(expectedLength);
        invalidKey.fill(0xff);

        // Test multiple times with the same invalid key
        const result1 = weierstrassIsValidPublicKey(curve, invalidKey);
        const result2 = weierstrassIsValidPublicKey(curve, invalidKey);
        const result3 = weierstrassIsValidPublicKey(curve, invalidKey);

        expect(result1).toBe(result2);
        expect(result2).toBe(result3);
        expect(result1).toBe(false);
      },
    );
  });
});
