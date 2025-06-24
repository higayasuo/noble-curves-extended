import { describe, it, expect } from 'vitest';
import { createSignatureCurve } from '../createSignatureCurve';
import { randomBytes } from '@noble/hashes/utils';
import type { SignatureCurveName } from '../../types';

describe('createSignatureCurve', () => {
  const supportedCurves = [
    { curveName: 'P-256', signatureAlgorithmName: 'ES256', compressed: false },
    { curveName: 'P-384', signatureAlgorithmName: 'ES384', compressed: false },
    { curveName: 'P-521', signatureAlgorithmName: 'ES512', compressed: false },
    {
      curveName: 'secp256k1',
      signatureAlgorithmName: 'ES256K',
      compressed: false,
    },
    { curveName: 'Ed25519', signatureAlgorithmName: 'EdDSA', compressed: true },
  ] as const;

  describe('valid curve creation', () => {
    it.each(supportedCurves)(
      'should create signature curve instance for $curveName',
      ({ curveName }) => {
        const signatureCurve = createSignatureCurve(curveName, randomBytes);

        expect(signatureCurve).toBeDefined();
        expect(signatureCurve.curveName).toBe(curveName);
        expect(signatureCurve.randomBytes).toBe(randomBytes);
        expect(typeof signatureCurve.randomPrivateKey).toBe('function');
        expect(typeof signatureCurve.getPublicKey).toBe('function');
        expect(typeof signatureCurve.sign).toBe('function');
        expect(typeof signatureCurve.verify).toBe('function');
        expect(typeof signatureCurve.recoverPublicKey).toBe('function');
        expect(typeof signatureCurve.toJwkPrivateKey).toBe('function');
        expect(typeof signatureCurve.toJwkPublicKey).toBe('function');
        expect(typeof signatureCurve.toRawPrivateKey).toBe('function');
        expect(typeof signatureCurve.toRawPublicKey).toBe('function');
        expect(signatureCurve.signatureAlgorithmName).toBeDefined();
      },
    );
  });

  describe('curveName property', () => {
    it.each(supportedCurves)(
      'should set correct curveName for $curveName',
      ({ curveName }) => {
        const signatureCurve = createSignatureCurve(curveName, randomBytes);
        expect(signatureCurve.curveName).toBe(curveName);
      },
    );
  });

  describe('signatureAlgorithmName property', () => {
    it.each(supportedCurves)(
      'should create $curveName signature curve instance with correct algorithm $signatureAlgorithmName',
      ({ curveName, signatureAlgorithmName }) => {
        const signatureCurve = createSignatureCurve(curveName, randomBytes);
        expect(signatureCurve.signatureAlgorithmName).toBe(
          signatureAlgorithmName,
        );
      },
    );
  });

  describe('signature operations', () => {
    it.each(supportedCurves)(
      'should be able to sign and verify messages with $curveName',
      ({ curveName }) => {
        const signatureCurve = createSignatureCurve(curveName, randomBytes);
        const privateKey = signatureCurve.randomPrivateKey();
        const publicKey = signatureCurve.getPublicKey(privateKey);
        const message = new TextEncoder().encode('Hello, World!');

        const signature = signatureCurve.sign({ privateKey, message });
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBeGreaterThan(0);

        const isValid = signatureCurve.verify({
          publicKey,
          message,
          signature,
        });
        expect(isValid).toBe(true);
      },
    );
  });

  describe('public key recovery', () => {
    it.each(['P-256', 'P-384', 'P-521', 'secp256k1'])(
      'should be able to recover public key from signature with $curveName',
      (curveName) => {
        const signatureCurve = createSignatureCurve(
          curveName as SignatureCurveName,
          randomBytes,
        );
        const privateKey = signatureCurve.randomPrivateKey();
        const expectedPublicKey = signatureCurve.getPublicKey(privateKey);
        const message = new TextEncoder().encode('Hello, World!');

        const signature = signatureCurve.sign({
          privateKey,
          message,
          recovered: true,
        });
        const recoveredPublicKey = signatureCurve.recoverPublicKey({
          signature,
          message,
        });

        expect(recoveredPublicKey).toEqual(expectedPublicKey);
      },
    );

    it('should throw error when trying to recover public key with Ed25519', () => {
      const signatureCurve = createSignatureCurve('Ed25519', randomBytes);
      const privateKey = signatureCurve.randomPrivateKey();
      const message = new TextEncoder().encode('Hello, World!');

      const sig = signatureCurve.sign({ privateKey, message });

      expect(() =>
        signatureCurve.recoverPublicKey({
          signature: sig,
          message,
        }),
      ).toThrow();
    });
  });

  describe('JWK operations', () => {
    it.each(supportedCurves)(
      'should be able to convert keys to and from JWK format with $curveName',
      ({ curveName, compressed }) => {
        const signatureCurve = createSignatureCurve(curveName, randomBytes);
        const privateKey = signatureCurve.randomPrivateKey();
        const publicKey = signatureCurve.getPublicKey(privateKey, compressed);

        const jwkPrivateKey = signatureCurve.toJwkPrivateKey(privateKey);
        const jwkPublicKey = signatureCurve.toJwkPublicKey(publicKey);

        expect(jwkPrivateKey).toBeDefined();
        expect(jwkPublicKey).toBeDefined();
        expect(jwkPrivateKey.kty).toBeDefined();
        expect(jwkPrivateKey.crv).toBeDefined();
        expect(jwkPrivateKey.d).toBeDefined();
        expect(jwkPrivateKey.x).toBeDefined();
        expect(jwkPublicKey.kty).toBeDefined();
        expect(jwkPublicKey.crv).toBeDefined();
        expect(jwkPublicKey.x).toBeDefined();

        const recoveredPrivateKey =
          signatureCurve.toRawPrivateKey(jwkPrivateKey);
        const recoveredPublicKey = signatureCurve.toRawPublicKey(jwkPublicKey);

        expect(recoveredPrivateKey).toEqual(privateKey);
        expect(recoveredPublicKey).toEqual(publicKey);
      },
    );
  });

  describe('error handling', () => {
    it('should throw error for unsupported curve name', () => {
      expect(() =>
        createSignatureCurve('X25519' as SignatureCurveName, randomBytes),
      ).toThrow('Unsupported signature curve: X25519');
    });

    it('should throw error for invalid curve name', () => {
      expect(() =>
        createSignatureCurve('InvalidCurve' as SignatureCurveName, randomBytes),
      ).toThrow('Unsupported signature curve: InvalidCurve');
    });

    it('should throw error for empty curve name', () => {
      expect(() =>
        createSignatureCurve('' as SignatureCurveName, randomBytes),
      ).toThrow('Unsupported signature curve: ');
    });
  });
});
