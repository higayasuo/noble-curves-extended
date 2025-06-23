import { describe, it, expect } from 'vitest';
import { fromRawSignature } from '../fromRawSignature';
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
    describe('recovery bit validation', () => {
      it.each(curves)(
        'should have valid recovery bit in recoverable signature for $name',
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

          // Convert to raw signature using toRawRecoveredSignature
          const rawSignature = toRawRecoveredSignature(signature);

          // Verify recovery bit is set correctly
          expect(rawSignature[rawSignature.length - 1]).toBe(
            signature.recovery,
          );
          expect(rawSignature[rawSignature.length - 1]).toBeGreaterThanOrEqual(
            0,
          );

          // Convert using fromRawSignature
          const convertedSignature = fromRawSignature(curve, rawSignature);

          // Verify converted signature has recovery bit
          expect(convertedSignature.recovery).not.toBeNull();
          expect(convertedSignature.recovery).not.toBeUndefined();
          expect(convertedSignature.recovery).toBe(signature.recovery);
        },
      );
    });

    describe('verify recoverable signature', () => {
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

          // Convert to raw signature using toRawRecoveredSignature
          const rawSignature = toRawRecoveredSignature(signature);

          // Convert using fromRawSignature
          const convertedSignature = fromRawSignature(curve, rawSignature);

          // Verify that the converted signature works
          const isValid = curve.verify(convertedSignature, message, publicKey, {
            prehash: true,
          });
          expect(isValid).toBe(true);
        },
      );
    });
  });

  describe('public key recovery', () => {
    describe('uncompressed public key recovery', () => {
      it.each(curves)(
        'should recover public key from recoverable signature for $name',
        ({ createCurve }) => {
          const curve = createCurve(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const expectedPublicKey = curve.getPublicKey(privateKey, false); // uncompressed
          const message = Uint8Array.from(
            new TextEncoder().encode('Hello, World!'),
          );

          // Create a recoverable signature using the curve
          const signature = curve.sign(message, privateKey, {
            prehash: true,
          });

          // Convert to raw signature using toRawRecoveredSignature
          const rawSignature = toRawRecoveredSignature(signature);

          // Convert using fromRawSignature
          const convertedSignature = fromRawSignature(curve, rawSignature);

          // Recover public key
          const messageHash = curve.CURVE.hash(message);
          const recoveredPoint =
            convertedSignature.recoverPublicKey(messageHash);
          const recoveredPublicKey = recoveredPoint.toRawBytes(false); // uncompressed

          expect(recoveredPublicKey).toEqual(expectedPublicKey);
        },
      );
    });

    describe('compressed public key recovery', () => {
      it.each(curves)(
        'should recover compressed public key from recoverable signature for $name',
        ({ createCurve }) => {
          const curve = createCurve(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const expectedPublicKey = curve.getPublicKey(privateKey, true); // compressed
          const message = Uint8Array.from(
            new TextEncoder().encode('Hello, World!'),
          );

          // Create a recoverable signature using the curve
          const signature = curve.sign(message, privateKey, {
            prehash: true,
          });

          // Convert to raw signature using toRawRecoveredSignature
          const rawSignature = toRawRecoveredSignature(signature);

          // Convert using fromRawSignature
          const convertedSignature = fromRawSignature(curve, rawSignature);

          // Recover public key (compressed)
          const messageHash = curve.CURVE.hash(message);
          const recoveredPoint =
            convertedSignature.recoverPublicKey(messageHash);
          const recoveredPublicKey = recoveredPoint.toRawBytes(true); // compressed

          expect(recoveredPublicKey).toEqual(expectedPublicKey);
        },
      );
    });
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
