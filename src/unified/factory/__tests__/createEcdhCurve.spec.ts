import { describe, it, expect } from 'vitest';
import { createEcdhCurve } from '../createEcdhCurve';
import { randomBytes } from '@noble/hashes/utils';
import type { EcdhCurveName } from '../../types';

describe('createEcdhCurve', () => {
  const supportedCurves = [
    { curveName: 'P-256', compressed: false },
    { curveName: 'P-384', compressed: false },
    { curveName: 'P-521', compressed: false },
    { curveName: 'secp256k1', compressed: false },
    { curveName: 'X25519', compressed: true },
  ] as const;

  describe('valid curve creation', () => {
    it.each(supportedCurves)(
      'should create ECDH curve instance for $curveName',
      ({ curveName }) => {
        const ecdhCurve = createEcdhCurve(curveName, randomBytes);

        expect(ecdhCurve).toBeDefined();
        expect(ecdhCurve.curveName).toBe(curveName);
        expect(ecdhCurve.randomBytes).toBe(randomBytes);
        expect(typeof ecdhCurve.randomPrivateKey).toBe('function');
        expect(typeof ecdhCurve.getPublicKey).toBe('function');
        expect(typeof ecdhCurve.getSharedSecret).toBe('function');
        expect(typeof ecdhCurve.toJwkPrivateKey).toBe('function');
        expect(typeof ecdhCurve.toJwkPublicKey).toBe('function');
        expect(typeof ecdhCurve.toRawPrivateKey).toBe('function');
        expect(typeof ecdhCurve.toRawPublicKey).toBe('function');
      },
    );
  });

  describe('ECDH operations', () => {
    it.each(supportedCurves)(
      'should be able to generate keys and compute shared secret with $curveName',
      ({ curveName }) => {
        const ecdhCurve = createEcdhCurve(curveName, randomBytes);
        const alicePrivateKey = ecdhCurve.randomPrivateKey();
        const alicePublicKey = ecdhCurve.getPublicKey(alicePrivateKey);
        const bobPrivateKey = ecdhCurve.randomPrivateKey();
        const bobPublicKey = ecdhCurve.getPublicKey(bobPrivateKey);

        const aliceSharedSecret = ecdhCurve.getSharedSecret({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey,
        });
        const bobSharedSecret = ecdhCurve.getSharedSecret({
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey,
        });

        expect(aliceSharedSecret).toBeInstanceOf(Uint8Array);
        expect(aliceSharedSecret.length).toBeGreaterThan(0);
        expect(aliceSharedSecret).toEqual(bobSharedSecret);
      },
    );
  });

  describe('JWK operations', () => {
    it.each(supportedCurves)(
      'should be able to convert keys to and from JWK format with $curveName',
      ({ curveName, compressed }) => {
        const ecdhCurve = createEcdhCurve(curveName, randomBytes);
        const privateKey = ecdhCurve.randomPrivateKey();
        const publicKey = ecdhCurve.getPublicKey(privateKey, compressed);

        const jwkPrivateKey = ecdhCurve.toJwkPrivateKey(privateKey);
        const jwkPublicKey = ecdhCurve.toJwkPublicKey(publicKey);

        expect(jwkPrivateKey).toBeDefined();
        expect(jwkPublicKey).toBeDefined();
        expect(jwkPrivateKey.kty).toBeDefined();
        expect(jwkPrivateKey.crv).toBeDefined();
        expect(jwkPrivateKey.d).toBeDefined();
        expect(jwkPrivateKey.x).toBeDefined();
        expect(jwkPublicKey.kty).toBeDefined();
        expect(jwkPublicKey.crv).toBeDefined();
        expect(jwkPublicKey.x).toBeDefined();

        const recoveredPrivateKey = ecdhCurve.toRawPrivateKey(jwkPrivateKey);
        const recoveredPublicKey = ecdhCurve.toRawPublicKey(jwkPublicKey);

        expect(recoveredPrivateKey).toEqual(privateKey);
        expect(recoveredPublicKey).toEqual(publicKey);
      },
    );
  });

  describe('error handling', () => {
    it('should throw error for unsupported curve name', () => {
      expect(() =>
        createEcdhCurve('Ed25519' as EcdhCurveName, randomBytes),
      ).toThrow('Unsupported signature curve: Ed25519');
    });

    it('should throw error for invalid curve name', () => {
      expect(() =>
        createEcdhCurve('InvalidCurve' as EcdhCurveName, randomBytes),
      ).toThrow('Unsupported signature curve: InvalidCurve');
    });

    it('should throw error for empty curve name', () => {
      expect(() => createEcdhCurve('' as EcdhCurveName, randomBytes)).toThrow(
        'Unsupported signature curve: ',
      );
    });
  });
});
