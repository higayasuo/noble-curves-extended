import { describe, it, expect } from 'vitest';
import { toRawRecoveredSignature } from '../toRawRecoveredSignature';
import { createP256 } from '../p256';
import { createP384 } from '../p384';
import { createP521 } from '../p521';
import { createSecp256k1 } from '../secp256k1';
import { randomBytes } from '@noble/hashes/utils';

const curves = [
  {
    name: 'P-256',
    createCurve: createP256,
  },
  {
    name: 'P-384',
    createCurve: createP384,
  },
  {
    name: 'P-521',
    createCurve: createP521,
  },
  {
    name: 'secp256k1',
    createCurve: createSecp256k1,
  },
];

const message = new TextEncoder().encode('Hello, World!');

describe('toRawRecoveredSignature', () => {
  describe('basic conversion tests', () => {
    it.each(curves)(
      'should convert RecoveredSignatureType to raw signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();

        // Create a signature using the curve
        const signature = curve.sign(message, privateKey, { prehash: true });

        // Convert to raw signature
        const rawSignature = toRawRecoveredSignature(signature);

        expect(rawSignature).toBeInstanceOf(Uint8Array);
        expect(rawSignature.length).toBe(curve.CURVE.nByteLength * 2 + 1); // +1 for recovery byte
        expect(rawSignature.slice(0, -1)).toEqual(
          signature.toCompactRawBytes(),
        );
        expect(rawSignature[rawSignature.length - 1]).toBe(signature.recovery);
      },
    );
  });

  describe('error handling tests', () => {
    it('should throw error for null signature', () => {
      expect(() => toRawRecoveredSignature(null as any)).toThrow();
    });

    it('should throw error for undefined signature', () => {
      expect(() => toRawRecoveredSignature(undefined as any)).toThrow();
    });

    it('should throw error for signature without recovery property', () => {
      const invalidSignature = {
        toCompactRawBytes: () => new Uint8Array(32),
        // Missing recovery property
      };
      expect(() => toRawRecoveredSignature(invalidSignature as any)).toThrow();
    });

    it('should throw error for signature without toCompactRawBytes method', () => {
      const invalidSignature = {
        recovery: 0,
        // Missing toCompactRawBytes method
      };
      expect(() => toRawRecoveredSignature(invalidSignature as any)).toThrow();
    });
  });
});
