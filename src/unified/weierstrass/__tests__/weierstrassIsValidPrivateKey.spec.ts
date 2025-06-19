import { describe, it, expect } from 'vitest';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { weierstrassIsValidPrivateKey } from '../weierstrassIsValidPrivateKey';
import { weierstrassRandomPrivateKey } from '../weierstrassRandomPrivateKey';
import { randomBytes } from '@noble/hashes/utils';

describe('weierstrassIsValidPrivateKey', () => {
  const curves = [
    { name: 'P-256', createCurve: createP256, expectedLength: 32 },
    { name: 'P-384', createCurve: createP384, expectedLength: 48 },
    { name: 'P-521', createCurve: createP521, expectedLength: 66 },
    { name: 'secp256k1', createCurve: createSecp256k1, expectedLength: 32 },
  ];

  it.each(curves)(
    'should validate a valid $name private key',
    ({ createCurve }) => {
      const curve = createCurve(randomBytes);
      const privateKey = weierstrassRandomPrivateKey(curve);
      expect(weierstrassIsValidPrivateKey(curve, privateKey)).toBe(true);
    },
  );

  it.each(curves)(
    'should reject an invalid $name private key length',
    ({ createCurve, expectedLength }) => {
      const curve = createCurve(randomBytes);
      const invalidKey = new Uint8Array(expectedLength - 1); // Too short
      expect(weierstrassIsValidPrivateKey(curve, invalidKey)).toBe(false);
    },
  );

  it.each(curves)(
    'should reject an oversized $name private key',
    ({ createCurve, expectedLength }) => {
      const curve = createCurve(randomBytes);
      const oversizedKey = new Uint8Array(expectedLength + 1); // Too long
      expect(weierstrassIsValidPrivateKey(curve, oversizedKey)).toBe(false);
    },
  );

  it.each(curves)(
    'should reject an all-zero $name private key',
    ({ createCurve, expectedLength }) => {
      const curve = createCurve(randomBytes);
      const zeroKey = new Uint8Array(expectedLength); // All zeros
      expect(weierstrassIsValidPrivateKey(curve, zeroKey)).toBe(false);
    },
  );

  it.each(curves)(
    'should reject an empty $name private key',
    ({ createCurve }) => {
      const curve = createCurve(randomBytes);
      const emptyKey = new Uint8Array(0);
      expect(weierstrassIsValidPrivateKey(curve, emptyKey)).toBe(false);
    },
  );
});
