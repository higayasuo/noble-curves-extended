import { describe, it, expect } from 'vitest';
import { weierstrassToJwkPrivateKey } from '../weierstrassToJwkPrivateKey';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { decodeBase64Url } from 'u8a-utils';
import type { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { CurveName, SignatureAlgorithmName } from '../../types';

describe('weierstrassToJwkPrivateKey', () => {
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
      'should convert a valid $curveName private key to JWK format',
      ({ curveName, createCurve, keyByteLength, signatureAlgorithm }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          keyByteLength,
          curveName,
          signatureAlgorithm,
          privateKey,
        );

        expect(jwk).toEqual({
          kty: 'EC',
          crv: curveName,
          alg: signatureAlgorithm,
          x: expect.any(String),
          y: expect.any(String),
          d: expect.any(String),
        });

        // d, x, and y should be valid base64url strings and decode to the correct lengths
        const decodedD = decodeBase64Url(jwk.d);
        const decodedX = decodeBase64Url(jwk.x);
        expect(jwk.y).toBeDefined();
        const decodedY = decodeBase64Url(jwk.y!);

        expect(decodedD).toEqual(privateKey);
        expect(decodedX.length).toBe(keyByteLength);
        expect(decodedY.length).toBe(keyByteLength);

        // Verify the public key coordinates match the derived public key
        const publicKey = curve.getPublicKey(privateKey, false);
        const expectedX = publicKey.slice(1, 1 + keyByteLength);
        const expectedY = publicKey.slice(1 + keyByteLength);
        expect(decodedX).toEqual(expectedX);
        expect(decodedY).toEqual(expectedY);

        // Verify crv and alg are strings
        expect(typeof jwk.crv).toBe('string');
        expect(jwk.crv!).toBe(curveName);
        expect(typeof jwk.alg).toBe('string');
        expect(jwk.alg!).toBe(signatureAlgorithm);
      },
    );

    it.each(curves.filter((curve) => curve.curveName !== 'secp256k1'))(
      'should generate a JWK that can be imported by Web Crypto API for $curveName',
      async ({ curveName, createCurve, keyByteLength }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          keyByteLength,
          curveName,
          curveName === 'secp256k1'
            ? 'ES256K'
            : curveName === 'P-256'
            ? 'ES256'
            : curveName === 'P-384'
            ? 'ES384'
            : 'ES512',
          privateKey,
        );

        const importedKey = await crypto.subtle.importKey(
          'jwk',
          jwk,
          {
            name: 'ECDSA',
            namedCurve: curveName,
          },
          false,
          ['sign'],
        );
        expect(importedKey).toBeDefined();
      },
    );
  });

  describe('error handling', () => {
    it('should throw an error for invalid private key length', () => {
      const curve = createP256(randomBytes);
      const invalidKey = new Uint8Array(16); // Too short
      expect(() =>
        weierstrassToJwkPrivateKey(curve, 32, 'P-256', 'ES256', invalidKey),
      ).toThrow('Failed to convert private key to JWK');
    });

    it('should throw an error for invalid private key format', () => {
      const curve = createP256(randomBytes);
      const invalidKey = new Uint8Array(33).fill(0); // Wrong length for P-256
      expect(() =>
        weierstrassToJwkPrivateKey(curve, 32, 'P-256', 'ES256', invalidKey),
      ).toThrow('Failed to convert private key to JWK');
    });
  });
});
