import { describe, it, expect } from 'vitest';
import {
  weierstrassToRawPrivateKey,
  weierstrassToRawPrivateKeyInternal,
} from '../weierstrassToRawPrivateKey';
import { weierstrassToJwkPrivateKey } from '../weierstrassToJwkPrivateKey';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';

describe('weierstrassToRawPrivateKey', () => {
  const curves = [
    {
      name: 'P-256',
      createCurve: () => createP256(randomBytes),
    },
    {
      name: 'P-384',
      createCurve: () => createP384(randomBytes),
    },
    {
      name: 'P-521',
      createCurve: () => createP521(randomBytes),
    },
    {
      name: 'secp256k1',
      createCurve: () => createSecp256k1(randomBytes),
    },
  ];

  describe('valid JWK conversion', () => {
    it.each(curves)(
      'should convert a valid $name JWK to raw private key',
      ({ createCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

        const rawPrivateKey = weierstrassToRawPrivateKey(curve, jwk);

        expect(rawPrivateKey).toEqual(privateKey);
        expect(rawPrivateKey.length).toBe(curve.CURVE.nByteLength);
      },
    );
  });

  describe('error handling', () => {
    describe('d parameter', () => {
      it.each(curves)(
        'should throw error for missing d in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const { d, ...jwkWithoutD } = jwk;

          expect(() =>
            weierstrassToRawPrivateKey(curve, jwkWithoutD as any),
          ).toThrow('Failed to convert JWK to raw private key');
        },
      );

      it.each(curves)(
        'should throw error for invalid d type in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const jwkWithInvalidDType = { ...jwk, d: 789 }; // Wrong type (number instead of string)

          expect(() =>
            weierstrassToRawPrivateKey(curve, jwkWithInvalidDType as any),
          ).toThrow('Failed to convert JWK to raw private key');
        },
      );

      it.each(curves)(
        'should throw error for invalid d encoding in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const jwkWithInvalidD = { ...jwk, d: 'invalid-base64url!@#' };

          expect(() =>
            weierstrassToRawPrivateKey(curve, jwkWithInvalidD as any),
          ).toThrow('Failed to convert JWK to raw private key');
        },
      );

      it.each(curves)(
        'should throw error for wrong d length in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

          // Create a JWK with wrong private key length by modifying the d parameter
          const jwkWithWrongD = { ...jwk, d: 'dGVzdA' }; // "test" in base64url, too short

          expect(() =>
            weierstrassToRawPrivateKey(curve, jwkWithWrongD),
          ).toThrow('Failed to convert JWK to raw private key');
        },
      );

      it.each(curves)(
        'should throw error for d that does not match public key in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey1 = curve.utils.randomPrivateKey();
          const privateKey2 = curve.utils.randomPrivateKey();

          // Create JWK with private key 1 but public key from private key 2
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey1);
          const jwk2 = weierstrassToJwkPrivateKey(curve, privateKey2);
          const jwkWithMismatchedD = {
            ...jwk,
            x: jwk2.x, // Use x from different key
            y: jwk2.y, // Use y from different key
          };

          expect(() =>
            weierstrassToRawPrivateKey(curve, jwkWithMismatchedD as any),
          ).toThrow('Failed to convert JWK to raw private key');
        },
      );
    });

    describe('inherited public key validation', () => {
      describe('kty parameter', () => {
        it.each(curves)(
          'should throw error for missing kty in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const { kty, ...jwkWithoutKty } = jwk;

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithoutKty as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );

        it.each(curves)(
          'should throw error for wrong kty in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const jwkWithWrongKty = { ...jwk, kty: 'RSA' };

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithWrongKty as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );
      });

      describe('crv parameter', () => {
        it.each(curves)(
          'should throw error for missing crv in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const { crv, ...jwkWithoutCrv } = jwk;

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithoutCrv as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );

        it.each(curves)(
          'should throw error for wrong crv in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const jwkWithWrongCrv = { ...jwk, crv: 'WrongCurve' };

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithWrongCrv as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );
      });

      describe('x parameter', () => {
        it.each(curves)(
          'should throw error for missing x in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const { x, ...jwkWithoutX } = jwk;

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithoutX as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );
      });

      describe('y parameter', () => {
        it.each(curves)(
          'should throw error for missing y in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const { y, ...jwkWithoutY } = jwk;

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithoutY as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );
      });

      describe('alg parameter', () => {
        it.each(curves)(
          'should throw error for wrong alg in $name JWK',
          ({ createCurve }) => {
            const curve = createCurve();
            const privateKey = curve.utils.randomPrivateKey();
            const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
            const jwkWithWrongAlg = { ...jwk, alg: 'ES123' };

            expect(() =>
              weierstrassToRawPrivateKey(curve, jwkWithWrongAlg as any),
            ).toThrow('Failed to convert JWK to raw private key');
          },
        );
      });
    });
  });

  describe('internal function', () => {
    it.each(curves)(
      'should work with internal function for $name',
      ({ createCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

        const rawPrivateKey = weierstrassToRawPrivateKeyInternal(curve, jwk);
        expect(rawPrivateKey).toEqual(privateKey);
      },
    );
  });
});
