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
import {
  CurveName,
  JwkPrivateKey,
  SignatureAlgorithmName,
} from '@/unified/types';
import { CurveFn } from '@noble/curves/abstract/weierstrass';

describe('weierstrassToRawPrivateKey', () => {
  const curves: {
    curveName: CurveName;
    createCurve: () => CurveFn;
    keyByteLength: number;
    signatureAlgorithm: SignatureAlgorithmName;
  }[] = [
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

  describe('weierstrassToRawPrivateKey', () => {
    it('should convert a valid JWK to raw private key', () => {
      const curve = createP256(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = weierstrassToJwkPrivateKey(
        curve,
        32,
        'P-256',
        'ES256',
        privateKey,
      );

      const rawPrivateKey = weierstrassToRawPrivateKey(
        curve,
        32,
        'P-256',
        'ES256',
        jwk,
      );

      expect(rawPrivateKey).toEqual(privateKey);
      expect(rawPrivateKey.length).toBe(32);
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createP256(randomBytes);
      const invalidJwk = { kty: 'RSA' } as JwkPrivateKey;

      expect(() =>
        weierstrassToRawPrivateKey(curve, 32, 'P-256', 'ES256', invalidJwk),
      ).toThrow('Failed to convert JWK to raw private key');
    });
  });

  describe('weierstrassToRawPrivateKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it.each(curves)(
        'should convert a valid $curveName JWK to raw private key',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );

          const rawPrivateKey = weierstrassToRawPrivateKeyInternal(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            jwk,
          );

          expect(rawPrivateKey).toEqual(privateKey);
          expect(rawPrivateKey.length).toBe(keyByteLength);
        },
      );

      it.each(curves)(
        'should accept JWK without alg parameter for $curveName',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );
          const { alg, ...jwkWithoutAlg } = jwk;

          const rawPrivateKey = weierstrassToRawPrivateKeyInternal(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            jwkWithoutAlg as JwkPrivateKey,
          );

          expect(rawPrivateKey).toEqual(privateKey);
        },
      );
    });

    describe('d parameter validation', () => {
      it.each(curves)(
        'should throw error for missing d in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );
          const { d, ...jwkWithoutD } = jwk;

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithoutD as JwkPrivateKey,
            ),
          ).toThrow('Missing required parameter for d');
        },
      );

      it.each(curves)(
        'should throw error for null d in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );
          const jwkWithNullD = { ...jwk, d: null } as unknown as JwkPrivateKey;

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithNullD,
            ),
          ).toThrow('Missing required parameter for d');
        },
      );

      it.each(curves)(
        'should throw error for invalid d type in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );
          const jwkWithInvalidDType = {
            ...jwk,
            d: 789,
          } as unknown as JwkPrivateKey;

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithInvalidDType,
            ),
          ).toThrow('Invalid parameter type for d');
        },
      );

      it.each(curves)(
        'should throw error for invalid d encoding in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );
          const jwkWithInvalidD = { ...jwk, d: 'invalid-base64url!@#' };

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithInvalidD,
            ),
          ).toThrow('Malformed encoding for d');
        },
      );

      it.each(curves)(
        'should throw error for wrong d length in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey,
          );

          // Create a shorter d parameter using proper base64url encoding
          const shortDBytes = new Uint8Array(Math.floor(keyByteLength / 2));
          const shortD = btoa(String.fromCharCode(...shortDBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          const jwkWithShortD = { ...jwk, d: shortD };

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithShortD,
            ),
          ).toThrow(
            `Invalid the length of the key data for d: ${Math.floor(
              keyByteLength / 2,
            )}, expected ${keyByteLength}`,
          );
        },
      );

      it.each(curves)(
        'should throw error for d that does not match public key in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
          const curve = createCurve();
          const privateKey1 = curve.utils.randomPrivateKey();
          const privateKey2 = curve.utils.randomPrivateKey();

          // Create JWK with private key 1 but public key from private key 2
          const jwk = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey1,
          );
          const jwk2 = weierstrassToJwkPrivateKey(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            privateKey2,
          );
          const jwkWithMismatchedD = {
            ...jwk,
            x: jwk2.x, // Use x from different key
            y: jwk2.y, // Use y from different key
          };

          expect(() =>
            weierstrassToRawPrivateKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
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
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          32,
          'P-256',
          'ES256',
          privateKey,
        );
        const jwkWithWrongKty = { ...jwk, kty: 'RSA' };

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            32,
            'P-256',
            'ES256',
            jwkWithWrongKty as JwkPrivateKey,
          ),
        ).toThrow('Invalid key type: RSA, expected EC');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for wrong crv', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          32,
          'P-256',
          'ES256',
          privateKey,
        );
        const jwkWithWrongCrv = { ...jwk, crv: 'WrongCurve' };

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            32,
            'P-256',
            'ES256',
            jwkWithWrongCrv as JwkPrivateKey,
          ),
        ).toThrow(`Invalid curve: WrongCurve, expected ${jwk.crv}`);
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          32,
          'P-256',
          'ES256',
          privateKey,
        );
        const { x, ...jwkWithoutX } = jwk;

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            32,
            'P-256',
            'ES256',
            jwkWithoutX as JwkPrivateKey,
          ),
        ).toThrow('Missing required parameter for x');
      });
    });

    describe('y parameter validation', () => {
      it('should throw error for missing y', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          32,
          'P-256',
          'ES256',
          privateKey,
        );
        const { y, ...jwkWithoutY } = jwk;

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            32,
            'P-256',
            'ES256',
            jwkWithoutY as JwkPrivateKey,
          ),
        ).toThrow('Missing required parameter for y');
      });
    });

    describe('alg parameter validation', () => {
      it('should throw error for wrong alg', () => {
        const curve = createP256(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = weierstrassToJwkPrivateKey(
          curve,
          32,
          'P-256',
          'ES256',
          privateKey,
        );
        const jwkWithWrongAlg = { ...jwk, alg: 'ES123' };

        expect(() =>
          weierstrassToRawPrivateKeyInternal(
            curve,
            32,
            'P-256',
            'ES256',
            jwkWithWrongAlg as JwkPrivateKey,
          ),
        ).toThrow(`Invalid algorithm: ES123, expected ${jwk.alg}`);
      });
    });
  });
});
