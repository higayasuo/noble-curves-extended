import { describe, it, expect } from 'vitest';
import { weierstrassToJwkPrivateKey } from '../weierstrassToJwkPrivateKey';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { decodeBase64Url } from 'u8a-utils';

describe('weierstrassToJwkPrivateKey', () => {
  const curves = [
    {
      name: 'P-256',
      createCurve: () => createP256(randomBytes),
      coordinateLength: 32,
      webCryptoCurve: 'P-256',
      signatureAlgorithm: 'ES256',
    },
    {
      name: 'P-384',
      createCurve: () => createP384(randomBytes),
      coordinateLength: 48,
      webCryptoCurve: 'P-384',
      signatureAlgorithm: 'ES384',
    },
    {
      name: 'P-521',
      createCurve: () => createP521(randomBytes),
      coordinateLength: 66,
      webCryptoCurve: 'P-521',
      signatureAlgorithm: 'ES512',
    },
    {
      name: 'secp256k1',
      createCurve: () => createSecp256k1(randomBytes),
      coordinateLength: 32,
      webCryptoCurve: 'secp256k1',
      signatureAlgorithm: 'ES256K',
    },
  ];

  describe('valid curves', () => {
    it.each(curves)(
      'should convert a valid $name private key to JWK format',
      ({ name, createCurve, coordinateLength, signatureAlgorithm }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

        expect(jwk).toEqual({
          kty: 'EC',
          crv: name,
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
        expect(decodedX.length).toBe(coordinateLength);
        expect(decodedY.length).toBe(coordinateLength);

        // Verify the public key coordinates match the derived public key
        const publicKey = curve.getPublicKey(privateKey, false);
        const expectedX = publicKey.slice(1, 1 + coordinateLength);
        const expectedY = publicKey.slice(1 + coordinateLength);
        expect(decodedX).toEqual(expectedX);
        expect(decodedY).toEqual(expectedY);

        // Verify crv and alg are strings
        expect(typeof jwk.crv).toBe('string');
        expect(jwk.crv!).toBe(name);
        expect(typeof jwk.alg).toBe('string');
        expect(jwk.alg!).toBe(signatureAlgorithm);
      },
    );

    it.each(curves.filter((curve) => curve.name !== 'secp256k1'))(
      'should generate a JWK that can be imported by Web Crypto API for $name',
      async ({ createCurve, webCryptoCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

        const importedKey = await crypto.subtle.importKey(
          'jwk',
          jwk,
          {
            name: 'ECDSA',
            namedCurve: webCryptoCurve,
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
      expect(() => weierstrassToJwkPrivateKey(curve, invalidKey)).toThrow(
        'Failed to convert private key to JWK',
      );
    });

    it('should throw an error for invalid private key format', () => {
      const curve = createP256(randomBytes);
      const invalidKey = new Uint8Array(33).fill(0); // Wrong length for P-256
      expect(() => weierstrassToJwkPrivateKey(curve, invalidKey)).toThrow(
        'Failed to convert private key to JWK',
      );
    });
  });
});
