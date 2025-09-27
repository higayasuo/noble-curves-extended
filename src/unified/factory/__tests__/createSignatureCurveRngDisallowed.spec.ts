import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { createSignatureCurve } from '../createSignatureCurve';
import { createSignatureCurveRngDisallowed } from '../createSignatureCurveRngDisallowed';
import type { SignatureCurveName } from '../../types';

describe('createSignatureCurveRngDisallowed', () => {
  const supportedCurves: {
    curveName: SignatureCurveName;
    compressed: boolean;
  }[] = [
    { curveName: 'P-256', compressed: false },
    { curveName: 'P-384', compressed: false },
    { curveName: 'P-521', compressed: false },
    { curveName: 'secp256k1', compressed: false },
    { curveName: 'Ed25519', compressed: true },
  ] as const;

  describe('valid curve creation', () => {
    it.each(supportedCurves)(
      'should create RNG-disallowed signature curve instance for $curveName',
      ({ curveName }) => {
        const curve = createSignatureCurveRngDisallowed(curveName);

        expect(curve).toBeDefined();
        expect(curve.curveName).toBe(curveName);
        expect(typeof curve.getPublicKey).toBe('function');
        expect(typeof curve.sign).toBe('function');
        expect(typeof curve.verify).toBe('function');
        expect(typeof curve.recoverPublicKey).toBe('function');
        expect(typeof curve.toJwkPrivateKey).toBe('function');
        expect(typeof curve.toJwkPublicKey).toBe('function');
        expect(typeof curve.toRawPrivateKey).toBe('function');
        expect(typeof curve.toRawPublicKey).toBe('function');

        // Type-level omission cannot be asserted at runtime; ensure RNG use throws instead
        const anyCurve = curve as unknown as Record<string, unknown> & {
          randomBytes?: (n?: number) => Uint8Array;
          randomPrivateKey?: () => Uint8Array;
        };

        // If present at runtime, RNG-related APIs should throw when invoked
        if (typeof anyCurve.randomBytes === 'function') {
          expect(() => anyCurve.randomBytes!()).toThrow(
            'RNG usage is disallowed for this curve',
          );
        }
        if (typeof anyCurve.randomPrivateKey === 'function') {
          expect(() => anyCurve.randomPrivateKey!()).toThrow();
        }
      },
    );
  });

  describe('signature operations without RNG', () => {
    it.each(supportedCurves)(
      'should sign and verify with provided private key for $curveName',
      ({ curveName, compressed }) => {
        const allowed = createSignatureCurve(curveName, randomBytes);
        const noRng = createSignatureCurveRngDisallowed(curveName);

        const privateKey = allowed.randomPrivateKey();
        const publicKey = noRng.getPublicKey(privateKey, compressed);

        const message = new TextEncoder().encode('Hello, RNG-free world!');
        const signature = noRng.sign({
          privateKey,
          message,
        });

        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBeGreaterThan(0);

        const isValid = noRng.verify({ publicKey, message, signature });
        expect(isValid).toBe(true);
      },
    );
  });

  describe('public key recovery behavior', () => {
    it.each(['P-256', 'P-384', 'P-521', 'secp256k1'])(
      'should recover public key for $curveName',
      (curveName) => {
        const allowed = createSignatureCurve(
          curveName as SignatureCurveName,
          randomBytes,
        );
        const noRng = createSignatureCurveRngDisallowed(
          curveName as SignatureCurveName,
        );

        const privateKey = allowed.randomPrivateKey();
        const expectedPublicKey = noRng.getPublicKey(privateKey, false);

        const message = new TextEncoder().encode('recover me');
        const signature = noRng.sign({
          privateKey,
          message,
          recovered: true,
        });
        const recoveredPublicKey = noRng.recoverPublicKey({
          signature,
          message,
          compressed: false,
        });
        expect(recoveredPublicKey).toEqual(expectedPublicKey);
      },
    );
  });

  describe('error handling', () => {
    it('should throw error for unsupported curve name', () => {
      expect(() =>
        createSignatureCurveRngDisallowed('X25519' as SignatureCurveName),
      ).toThrow('Unsupported signature curve: X25519');
    });

    it('should throw error for invalid curve name', () => {
      expect(() =>
        createSignatureCurveRngDisallowed('InvalidCurve' as SignatureCurveName),
      ).toThrow('Unsupported signature curve: InvalidCurve');
    });

    it('should throw error for empty curve name', () => {
      expect(() =>
        createSignatureCurveRngDisallowed('' as SignatureCurveName),
      ).toThrow('Unsupported signature curve: ');
    });
  });
});
