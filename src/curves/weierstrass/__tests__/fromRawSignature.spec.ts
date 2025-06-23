import { describe, it, expect } from 'vitest';
import { fromRawSignature } from '../fromRawSignature';
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

describe('fromRawSignature', () => {
  describe('compact signature conversion', () => {
    it.each(curves)(
      'should convert compact signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, World!'),
        );

        // Create a signature using the curve
        const signature = curve.sign(message, privateKey, { prehash: true });
        const compactSignature = signature.toCompactRawBytes();

        // Convert using fromRawSignature
        const convertedSignature = fromRawSignature(curve, compactSignature);

        expect(convertedSignature).toBeDefined();
        expect(convertedSignature.toCompactRawBytes()).toEqual(
          compactSignature,
        );
      },
    );

    it.each(curves)(
      'should verify signature after conversion for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, World!'),
        );

        // Create a signature using the curve
        const originalSignature = curve.sign(message, privateKey, {
          prehash: true,
        });
        const compactSignature = originalSignature.toCompactRawBytes();

        // Convert using fromRawSignature
        const convertedSignature = fromRawSignature(curve, compactSignature);

        // Verify that the converted signature works
        const isValid = curve.verify(convertedSignature, message, publicKey, {
          prehash: true,
        });
        expect(isValid).toBe(true);
      },
    );
  });

  describe('recoverable signature conversion', () => {
    it.each(curves)(
      'should convert recoverable signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, World!'),
        );

        // Create a recoverable signature using the curve
        const signature = curve.sign(message, privateKey, {
          prehash: true,
        });
        const compactSignature = signature.toCompactRawBytes();

        const recoverableSignature = new Uint8Array(
          compactSignature.length + 1,
        );
        recoverableSignature.set(compactSignature);
        recoverableSignature[recoverableSignature.length - 1] =
          signature.recovery;

        // Convert using fromRawSignature
        const convertedSignature = fromRawSignature(
          curve,
          recoverableSignature,
        );

        expect(convertedSignature).toBeDefined();
        expect(convertedSignature.toCompactRawBytes()).toEqual(
          compactSignature,
        );
      },
    );

    it.each(curves)(
      'should verify recoverable signature after conversion for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, World!'),
        );

        // Create a recoverable signature using the curve
        const signature = curve.sign(message, privateKey, {
          prehash: true,
        });
        const compactSignature = signature.toCompactRawBytes();

        const recoverableSignature = new Uint8Array(
          compactSignature.length + 1,
        );
        recoverableSignature.set(compactSignature);
        recoverableSignature[recoverableSignature.length - 1] =
          signature.recovery;

        // Convert using fromRawSignature
        const convertedSignature = fromRawSignature(
          curve,
          recoverableSignature,
        );

        // Verify that the converted signature works
        const isValid = curve.verify(convertedSignature, message, publicKey, {
          prehash: true,
        });
        expect(isValid).toBe(true);
      },
    );
  });

  describe('error handling', () => {
    it.each(curves)(
      'should throw error for invalid signature length for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const invalidSignature = new Uint8Array(16); // Wrong length

        expect(() => fromRawSignature(curve, invalidSignature)).toThrow(
          'Invalid raw signature',
        );
      },
    );

    it.each(curves)(
      'should throw error for empty signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const emptySignature = new Uint8Array(0);

        expect(() => fromRawSignature(curve, emptySignature)).toThrow(
          'Invalid raw signature',
        );
      },
    );

    it.each(curves)(
      'should throw error for too long signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const tooLongSignature = new Uint8Array(
          curve.CURVE.nByteLength * 2 + 2,
        ); // Too long

        expect(() => fromRawSignature(curve, tooLongSignature)).toThrow(
          'Invalid raw signature',
        );
      },
    );
  });
});
