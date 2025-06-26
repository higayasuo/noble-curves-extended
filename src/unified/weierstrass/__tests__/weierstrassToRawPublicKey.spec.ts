import { describe, it, expect } from 'vitest';
import {
  weierstrassToRawPublicKey,
  weierstrassToRawPublicKeyInternal,
} from '../weierstrassToRawPublicKey';
import { weierstrassToJwkPublickKey } from '../weierstrassToJwkPublickKey';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { JwkPublicKey } from '@/unified/types';

describe('weierstrassToRawPublicKey', () => {
  const curves = [
    {
      name: 'P-256',
      createCurve: () => createP256(randomBytes),
      coordinateLength: 32,
      signatureAlgorithm: 'ES256',
    },
    {
      name: 'P-384',
      createCurve: () => createP384(randomBytes),
      coordinateLength: 48,
      signatureAlgorithm: 'ES384',
    },
    {
      name: 'P-521',
      createCurve: () => createP521(randomBytes),
      coordinateLength: 66,
      signatureAlgorithm: 'ES512',
    },
    {
      name: 'secp256k1',
      createCurve: () => createSecp256k1(randomBytes),
      coordinateLength: 32,
      signatureAlgorithm: 'ES256K',
    },
  ];

  describe('weierstrassToRawPublicKey', () => {
    it('should convert a valid JWK to raw public key', () => {
      const curve = createP256(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false);
      const jwk = weierstrassToJwkPublickKey(curve, publicKey);

      const rawPublicKey = weierstrassToRawPublicKey(curve, jwk);

      expect(rawPublicKey).toEqual(publicKey);
      expect(rawPublicKey[0]).toBe(0x04); // uncompressed format
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createP256(randomBytes);
      const invalidJwk = { kty: 'RSA' } as JwkPublicKey;

      expect(() => weierstrassToRawPublicKey(curve, invalidJwk)).toThrow(
        'Failed to convert JWK to raw public key',
      );
    });
  });

  describe('weierstrassToRawPublicKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it.each(curves)(
        'should convert a valid $name JWK to raw public key',
        ({ createCurve, coordinateLength }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);

          const rawPublicKey = weierstrassToRawPublicKeyInternal(curve, jwk);

          expect(rawPublicKey).toEqual(publicKey);
          expect(rawPublicKey[0]).toBe(0x04); // uncompressed format
          expect(rawPublicKey.length).toBe(1 + coordinateLength * 2);
        },
      );

      it.each(curves)(
        'should accept JWK without alg parameter for $name',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { alg, ...jwkWithoutAlg } = jwk;

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            jwkWithoutAlg as JwkPublicKey,
          );

          expect(rawPublicKey).toEqual(publicKey);
        },
      );
    });

    describe('kty parameter validation', () => {
      it.each(curves)(
        'should throw error for missing kty in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { kty, ...jwkWithoutKty } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithoutKty as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for kty');
        },
      );

      it.each(curves)(
        'should throw error for null kty in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithNullKty = { ...jwk, kty: null as any };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithNullKty),
          ).toThrow('Missing required parameter for kty');
        },
      );

      it.each(curves)(
        'should throw error for wrong kty in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithWrongKty = { ...jwk, kty: 'RSA' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithWrongKty as JwkPublicKey,
            ),
          ).toThrow('Invalid key type: RSA, expected EC');
        },
      );
    });

    describe('crv parameter validation', () => {
      it.each(curves)(
        'should throw error for missing crv in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { crv, ...jwkWithoutCrv } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithoutCrv as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for crv');
        },
      );

      it.each(curves)(
        'should throw error for null crv in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithNullCrv = { ...jwk, crv: null as any };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithNullCrv),
          ).toThrow('Missing required parameter for crv');
        },
      );

      it.each(curves)(
        'should throw error for wrong crv in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithWrongCrv = { ...jwk, crv: 'WrongCurve' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithWrongCrv as JwkPublicKey,
            ),
          ).toThrow(`Invalid curve: WrongCurve, expected ${jwk.crv}`);
        },
      );
    });

    describe('x parameter validation', () => {
      it.each(curves)(
        'should throw error for missing x in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { x, ...jwkWithoutX } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithoutX as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for x');
        },
      );

      it.each(curves)(
        'should throw error for null x in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithNullX = { ...jwk, x: null as any };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithNullX),
          ).toThrow('Missing required parameter for x');
        },
      );

      it.each(curves)(
        'should throw error for invalid x type in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithInvalidXType = { ...jwk, x: 123 as any };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithInvalidXType),
          ).toThrow('Invalid parameter type for x');
        },
      );

      it.each(curves)(
        'should throw error for invalid x encoding in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithInvalidX = { ...jwk, x: 'invalid-base64url!@#' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithInvalidX),
          ).toThrow('Malformed encoding for x');
        },
      );

      it.each(curves)(
        'should throw error for wrong x length in $name JWK',
        ({ createCurve, coordinateLength }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          // Create a shorter x coordinate using proper base64url encoding
          const shortXBytes = new Uint8Array(Math.floor(coordinateLength / 2));
          const shortX = btoa(String.fromCharCode(...shortXBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          const jwkWithShortX = { ...jwk, x: shortX };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithShortX),
          ).toThrow(
            `Invalid the length of the key data for x: ${Math.floor(
              coordinateLength / 2,
            )}, expected ${coordinateLength}`,
          );
        },
      );
    });

    describe('y parameter validation', () => {
      it.each(curves)(
        'should throw error for missing y in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { y, ...jwkWithoutY } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithoutY as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for y');
        },
      );

      it.each(curves)(
        'should throw error for null y in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithNullY = { ...jwk, y: null as any };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithNullY),
          ).toThrow('Missing required parameter for y');
        },
      );

      it.each(curves)(
        'should throw error for invalid y type in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithInvalidYType = { ...jwk, y: 456 as any };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithInvalidYType),
          ).toThrow('Invalid parameter type for y');
        },
      );

      it.each(curves)(
        'should throw error for invalid y encoding in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithInvalidY = { ...jwk, y: 'invalid-base64url!@#' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithInvalidY),
          ).toThrow('Malformed encoding for y');
        },
      );

      it.each(curves)(
        'should throw error for wrong y length in $name JWK',
        ({ createCurve, coordinateLength }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          // Create a longer y coordinate using proper base64url encoding
          const longYBytes = new Uint8Array(coordinateLength + 1);
          const longY = btoa(String.fromCharCode(...longYBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          const jwkWithLongY = { ...jwk, y: longY };

          expect(() =>
            weierstrassToRawPublicKeyInternal(curve, jwkWithLongY),
          ).toThrow(
            `Invalid the length of the key data for y: ${
              coordinateLength + 1
            }, expected ${coordinateLength}`,
          );
        },
      );
    });

    describe('alg parameter validation', () => {
      it.each(curves)(
        'should throw error for wrong alg in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithWrongAlg = { ...jwk, alg: 'ES123' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              jwkWithWrongAlg as JwkPublicKey,
            ),
          ).toThrow(`Invalid algorithm: ES123, expected ${jwk.alg}`);
        },
      );

      it.each(curves)(
        'should accept null alg in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithNullAlg = { ...jwk, alg: null as any };

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            jwkWithNullAlg,
          );
          expect(rawPublicKey).toEqual(publicKey);
        },
      );

      it.each(curves)(
        'should accept undefined alg in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithUndefinedAlg = { ...jwk, alg: undefined as any };

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            jwkWithUndefinedAlg,
          );
          expect(rawPublicKey).toEqual(publicKey);
        },
      );
    });
  });
});
