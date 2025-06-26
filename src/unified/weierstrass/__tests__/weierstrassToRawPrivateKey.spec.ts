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
import { JwkPrivateKey } from '@/unified/types';

describe('weierstrassToRawPrivateKey', () => {
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

  describe('weierstrassToRawPrivateKey', () => {
    it('should convert a valid JWK to raw private key', () => {
      const curve = createP256(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

      const rawPrivateKey = weierstrassToRawPrivateKey(curve, jwk);

      expect(rawPrivateKey).toEqual(privateKey);
      expect(rawPrivateKey.length).toBe(curve.CURVE.nByteLength);
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createP256(randomBytes);
      const invalidJwk = { kty: 'RSA' } as JwkPrivateKey;

      expect(() => weierstrassToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Failed to convert JWK to raw private key',
      );
    });
  });

  describe('weierstrassToRawPrivateKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it.each(curves)(
        'should convert a valid $name JWK to raw private key',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

          const rawPrivateKey = weierstrassToRawPrivateKeyInternal(curve, jwk);

          expect(rawPrivateKey).toEqual(privateKey);
          expect(rawPrivateKey.length).toBe(curve.CURVE.nByteLength);
        },
      );

      it.each(curves)(
        'should accept JWK without alg parameter for $name',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const { alg, ...jwkWithoutAlg } = jwk;

          const rawPrivateKey = weierstrassToRawPrivateKeyInternal(
            curve,
            jwkWithoutAlg as JwkPrivateKey,
          );

          expect(rawPrivateKey).toEqual(privateKey);
        },
      );
    });

    describe('d parameter validation', () => {
      it.each(curves)(
        'should throw error for missing d in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const { d, ...jwkWithoutD } = jwk;

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              jwkWithoutD as JwkPrivateKey,
            ),
          ).toThrow('Missing required parameter for d');
        },
      );

      it.each(curves)(
        'should throw error for null d in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const jwkWithNullD = { ...jwk, d: null as any };

          expect(() =>
            weierstrassToRawPrivateKeyInternal(curve, jwkWithNullD),
          ).toThrow('Missing required parameter for d');
        },
      );

      it.each(curves)(
        'should throw error for invalid d type in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
          const jwkWithInvalidDType = { ...jwk, d: 789 as any };

          expect(() =>
            weierstrassToRawPrivateKeyInternal(curve, jwkWithInvalidDType),
          ).toThrow('Invalid parameter type for d');
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
            weierstrassToRawPrivateKeyInternal(curve, jwkWithInvalidD),
          ).toThrow('Malformed encoding for d');
        },
      );

      it.each(curves)(
        'should throw error for wrong d length in $name JWK',
        ({ createCurve }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(curve, privateKey);

          // Create a shorter d parameter using proper base64url encoding
          const shortDBytes = new Uint8Array(
            Math.floor(curve.CURVE.nByteLength / 2),
          );
          const shortD = btoa(String.fromCharCode(...shortDBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          const jwkWithShortD = { ...jwk, d: shortD };

          expect(() =>
            weierstrassToRawPrivateKeyInternal(curve, jwkWithShortD),
          ).toThrow(
            `Invalid the length of the key data for d: ${Math.floor(
              curve.CURVE.nByteLength / 2,
            )}, expected ${curve.CURVE.nByteLength}`,
          );
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
            weierstrassToRawPrivateKeyInternal(
              curve,
              jwkWithMismatchedD as JwkPrivateKey,
            ),
          ).toThrow(
            'The public key derived from the private key does not match the public key in the JWK',
          );
        },
      );
    });

    describe('kty parameter validation', () => {
      it('should throw error for wrong kty', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
        const jwkWithWrongKty = { ...jwk, kty: 'RSA' };

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            jwkWithWrongKty as JwkPrivateKey,
          ),
        ).toThrow('Invalid key type: RSA, expected EC');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for wrong crv', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'WrongCurve' };

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            jwkWithWrongCrv as JwkPrivateKey,
          ),
        ).toThrow(`Invalid curve: WrongCurve, expected ${jwk.crv}`);
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
        const { x, ...jwkWithoutX } = jwk;

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            jwkWithoutX as JwkPrivateKey,
          ),
        ).toThrow('Missing required parameter for x');
      });
    });

    describe('y parameter validation', () => {
      it('should throw error for missing y', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
        const { y, ...jwkWithoutY } = jwk;

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            jwkWithoutY as JwkPrivateKey,
          ),
        ).toThrow('Missing required parameter for y');
      });
    });

    describe('alg parameter validation', () => {
      it('should throw error for wrong alg', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(curve, privateKey);
        const jwkWithWrongAlg = { ...jwk, alg: 'ES123' };

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            jwkWithWrongAlg as JwkPrivateKey,
          ),
        ).toThrow(`Invalid algorithm: ES123, expected ${jwk.alg}`);
      });
    });
  });
});
