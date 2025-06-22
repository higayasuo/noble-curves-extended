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

  describe('valid JWK conversion', () => {
    it.each(curves)(
      'should convert a valid $name JWK to raw public key',
      ({ createCurve, coordinateLength }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey, false); // uncompressed

        // Create JWK using the tested function
        const jwk = weierstrassToJwkPublickKey(curve, publicKey);

        const rawPublicKey = weierstrassToRawPublicKey(curve, jwk);

        expect(rawPublicKey).toEqual(publicKey);
        expect(rawPublicKey[0]).toBe(0x04); // uncompressed format
        expect(rawPublicKey.length).toBe(1 + coordinateLength * 2);
      },
    );
  });

  describe('error handling', () => {
    describe('kty parameter', () => {
      it.each(curves)(
        'should throw error for missing kty in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { kty, ...jwkWithoutKty } = jwk;

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithoutKty as any),
          ).toThrow('Failed to convert JWK to raw public key');
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
            weierstrassToRawPublicKey(curve, jwkWithWrongKty as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );
    });

    describe('crv parameter', () => {
      it.each(curves)(
        'should throw error for missing crv in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { crv, ...jwkWithoutCrv } = jwk;

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithoutCrv as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );

      it.each(curves)(
        'should throw error for wrong crv in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithWrongCrv = { ...jwk, crv: 'WrongCurve' }; // Wrong curve

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithWrongCrv as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );
    });

    describe('x parameter', () => {
      it.each(curves)(
        'should throw error for missing x in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { x, ...jwkWithoutX } = jwk;

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithoutX as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );

      it.each(curves)(
        'should throw error for invalid x type in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithInvalidXType = { ...jwk, x: 123 }; // Wrong type (number instead of string)

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithInvalidXType as any),
          ).toThrow('Failed to convert JWK to raw public key');
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
            weierstrassToRawPublicKey(curve, jwkWithInvalidX as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );
    });

    describe('y parameter', () => {
      it.each(curves)(
        'should throw error for missing y in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const { y, ...jwkWithoutY } = jwk;

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithoutY as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );

      it.each(curves)(
        'should throw error for invalid y type in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithInvalidYType = { ...jwk, y: 456 }; // Wrong type (number instead of string)

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithInvalidYType as any),
          ).toThrow('Failed to convert JWK to raw public key');
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
            weierstrassToRawPublicKey(curve, jwkWithInvalidY as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );
    });

    describe('alg parameter', () => {
      it.each(curves)(
        'should throw error for wrong alg in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false);

          const jwk = weierstrassToJwkPublickKey(curve, publicKey);
          const jwkWithWrongAlg = { ...jwk, alg: 'ES123' }; // Wrong algorithm

          expect(() =>
            weierstrassToRawPublicKey(curve, jwkWithWrongAlg as any),
          ).toThrow('Failed to convert JWK to raw public key');
        },
      );
    });
  });

  describe('internal function', () => {
    it.each(curves)(
      'should work with internal function for $name',
      ({ createCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey, false);

        const jwk = weierstrassToJwkPublickKey(curve, publicKey);

        const rawPublicKey = weierstrassToRawPublicKeyInternal(curve, jwk);
        expect(rawPublicKey).toEqual(publicKey);
      },
    );
  });
});
