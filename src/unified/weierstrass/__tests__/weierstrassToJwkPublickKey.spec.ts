import { describe, it, expect } from 'vitest';
import { weierstrassToJwkPublickKey } from '../weierstrassToJwkPublickKey';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { decodeBase64Url } from 'u8a-utils';
import type { CurveName, SignatureAlgorithmName } from '../../types';
import type { CurveFn } from '@noble/curves/abstract/weierstrass';

describe('weierstrassToJwkPublickKey', () => {
  const curves: Array<{
    curveName: CurveName;
    createCurve: () => CurveFn;
    keyByteLength: number;
    signatureAlgorithm: SignatureAlgorithmName;
  }> = [
    {
      curveName: 'P-256',
      createCurve: () => createP256(randomBytes),
      keyByteLength: 32,
      signatureAlgorithm: 'ES256',
    },
    {
      curveName: 'P-384',
      createCurve: () => createP384(randomBytes),
      keyByteLength: 48,
      signatureAlgorithm: 'ES384',
    },
    {
      curveName: 'P-521',
      createCurve: () => createP521(randomBytes),
      keyByteLength: 66,
      signatureAlgorithm: 'ES512',
    },
    {
      curveName: 'secp256k1',
      createCurve: () => createSecp256k1(randomBytes),
      keyByteLength: 32,
      signatureAlgorithm: 'ES256K',
    },
  ];

  describe('valid curves', () => {
    it.each(curves)(
      'should convert a valid $curveName public key to JWK format',
      ({ curveName, createCurve, keyByteLength, signatureAlgorithm }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey, false); // uncompressed
        const jwk = weierstrassToJwkPublickKey(
          curve,
          keyByteLength,
          curveName,
          signatureAlgorithm,
          publicKey,
        );

        expect(jwk).toEqual({
          kty: 'EC',
          crv: curveName,
          alg: signatureAlgorithm,
          x: expect.any(String),
          y: expect.any(String),
        });

        // x and y should be valid base64url strings and decode to the correct lengths
        const decodedX = decodeBase64Url(jwk.x);
        expect(jwk.y).toBeDefined();
        const decodedY = decodeBase64Url(jwk.y!);
        expect(decodedX.length).toBe(keyByteLength);
        expect(decodedY.length).toBe(keyByteLength);

        // Verify crv and alg are strings
        expect(typeof jwk.crv).toBe('string');
        expect(jwk.crv!).toBe(curveName);
        expect(typeof jwk.alg).toBe('string');
        expect(jwk.alg!).toBe(signatureAlgorithm);
      },
    );

    it.each(curves.filter((curve) => curve.curveName !== 'secp256k1'))(
      'should generate a JWK that can be imported by Web Crypto API for $curveName',
      async ({ curveName, createCurve, keyByteLength, signatureAlgorithm }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey, false);
        const jwk = weierstrassToJwkPublickKey(
          curve,
          keyByteLength,
          curveName,
          signatureAlgorithm,
          publicKey,
        );

        const importedKey = await crypto.subtle.importKey(
          'jwk',
          jwk,
          {
            name: 'ECDSA',
            namedCurve: curveName,
          },
          false,
          [],
        );
        expect(importedKey).toBeDefined();
      },
    );
  });

  describe('error handling', () => {
    it('should throw an error for invalid public key length', () => {
      const curve = createP256(randomBytes);
      const invalidKey = new Uint8Array(16); // Too short
      expect(() =>
        weierstrassToJwkPublickKey(curve, 32, 'P-256', 'ES256', invalidKey),
      ).toThrow('Failed to convert public key to JWK');
    });

    it('should throw an error for invalid public key format', () => {
      const curve = createP256(randomBytes);
      const invalidKey = new Uint8Array(65).fill(0); // Wrong format
      expect(() =>
        weierstrassToJwkPublickKey(curve, 32, 'P-256', 'ES256', invalidKey),
      ).toThrow('Failed to convert public key to JWK');
    });

    it('should throw an error when uncompressed public key length mismatches keyByteLength', () => {
      const curve = createP256(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false); // uncompressed 65 bytes
      // Deliberately pass wrong keyByteLength (P-256 expects 32, we pass 48)
      expect(() =>
        weierstrassToJwkPublickKey(curve, 48, 'P-256', 'ES256', publicKey),
      ).toThrow('Failed to convert public key to JWK');
    });
  });
});
