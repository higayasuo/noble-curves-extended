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
import {
  CurveName,
  JwkPublicKey,
  SignatureAlgorithmName,
} from '@/unified/types';
import { CurveFn } from '@noble/curves/abstract/weierstrass';

describe('weierstrassToRawPublicKey', () => {
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

  describe('weierstrassToRawPublicKey', () => {
    it('should convert a valid JWK to raw public key', () => {
      const curve = createP256(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false);
      const jwk = weierstrassToJwkPublickKey(
        curve,
        32,
        'P-256',
        'ES256',
        publicKey,
      );

      const rawPublicKey = weierstrassToRawPublicKey(
        curve,
        32,
        'P-256',
        'ES256',
        jwk,
      );

      expect(rawPublicKey).toEqual(publicKey);
      expect(rawPublicKey[0]).toBe(0x04); // uncompressed format
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createP256(randomBytes);
      const invalidJwk = { kty: 'RSA' } as JwkPublicKey;

      expect(() =>
        weierstrassToRawPublicKey(curve, 32, 'P-256', 'ES256', invalidJwk),
      ).toThrow('Failed to convert JWK to raw public key');
    });
  });

  describe('weierstrassToRawPublicKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it.each(curves)(
        'should convert a valid $curveName JWK to raw public key',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            jwk,
          );

          expect(rawPublicKey).toEqual(publicKey);
          expect(rawPublicKey[0]).toBe(0x04); // uncompressed format
          expect(rawPublicKey.length).toBe(1 + keyByteLength * 2);
        },
      );

      it.each(curves)(
        'should accept JWK without alg parameter for $curveName',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const { alg, ...jwkWithoutAlg } = jwk;

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            jwkWithoutAlg as JwkPublicKey,
          );

          expect(rawPublicKey).toEqual(publicKey);
        },
      );
    });

    describe('kty parameter validation', () => {
      it.each(curves)(
        'should throw error for missing kty in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const { kty, ...jwkWithoutKty } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithoutKty as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for kty');
        },
      );

      it.each(curves)(
        'should throw error for null kty in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithNullKty = {
            ...jwk,
            kty: null,
          } as unknown as JwkPublicKey;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithNullKty,
            ),
          ).toThrow('Missing required parameter for kty');
        },
      );

      it.each(curves)(
        'should throw error for wrong kty in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithWrongKty = { ...jwk, kty: 'RSA' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithWrongKty as JwkPublicKey,
            ),
          ).toThrow('Invalid key type: RSA, expected EC');
        },
      );
    });

    describe('crv parameter validation', () => {
      it.each(curves)(
        'should throw error for missing crv in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const { crv, ...jwkWithoutCrv } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithoutCrv as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for crv');
        },
      );

      it.each(curves)(
        'should throw error for null crv in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithNullCrv = {
            ...jwk,
            crv: null,
          } as unknown as JwkPublicKey;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithNullCrv,
            ),
          ).toThrow('Missing required parameter for crv');
        },
      );

      it.each(curves)(
        'should throw error for wrong crv in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithWrongCrv = { ...jwk, crv: 'WrongCurve' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithWrongCrv as JwkPublicKey,
            ),
          ).toThrow(`Invalid curve: WrongCurve, expected ${jwk.crv}`);
        },
      );
    });

    describe('x parameter validation', () => {
      it.each(curves)(
        'should throw error for missing x in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const { x, ...jwkWithoutX } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithoutX as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for x');
        },
      );

      it.each(curves)(
        'should throw error for null x in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithNullX = { ...jwk, x: null } as unknown as JwkPublicKey;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithNullX,
            ),
          ).toThrow('Missing required parameter for x');
        },
      );

      it.each(curves)(
        'should throw error for invalid x type in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithInvalidXType = {
            ...jwk,
            x: 123,
          } as unknown as JwkPublicKey;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithInvalidXType,
            ),
          ).toThrow('Invalid parameter type for x');
        },
      );

      it.each(curves)(
        'should throw error for invalid x encoding in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithInvalidX = { ...jwk, x: 'invalid-base64url!@#' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithInvalidX,
            ),
          ).toThrow('Malformed encoding for x');
        },
      );

      it.each(curves)(
        'should throw error for wrong x length in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          // Create a shorter x coordinate using proper base64url encoding
          const shortXBytes = new Uint8Array(Math.floor(keyByteLength / 2));
          const shortX = btoa(String.fromCharCode(...shortXBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          const jwkWithShortX = { ...jwk, x: shortX };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithShortX,
            ),
          ).toThrow(
            `Invalid the length of the key data for x: ${Math.floor(
              keyByteLength / 2,
            )}, expected ${keyByteLength}`,
          );
        },
      );
    });

    describe('y parameter validation', () => {
      it.each(curves)(
        'should throw error for missing y in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const { y, ...jwkWithoutY } = jwk;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithoutY as JwkPublicKey,
            ),
          ).toThrow('Missing required parameter for y');
        },
      );

      it.each(curves)(
        'should throw error for null y in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithNullY = { ...jwk, y: null } as unknown as JwkPublicKey;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithNullY,
            ),
          ).toThrow('Missing required parameter for y');
        },
      );

      it.each(curves)(
        'should throw error for invalid y type in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithInvalidYType = {
            ...jwk,
            y: 456,
          } as unknown as JwkPublicKey;

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithInvalidYType,
            ),
          ).toThrow('Invalid parameter type for y');
        },
      );

      it.each(curves)(
        'should throw error for invalid y encoding in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithInvalidY = { ...jwk, y: 'invalid-base64url!@#' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithInvalidY,
            ),
          ).toThrow('Malformed encoding for y');
        },
      );

      it.each(curves)(
        'should throw error for wrong y length in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          // Create a longer y coordinate using proper base64url encoding
          const longYBytes = new Uint8Array(keyByteLength + 1);
          const longY = btoa(String.fromCharCode(...longYBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          const jwkWithLongY = { ...jwk, y: longY };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithLongY,
            ),
          ).toThrow(
            `Invalid the length of the key data for y: ${
              keyByteLength + 1
            }, expected ${keyByteLength}`,
          );
        },
      );
    });

    describe('alg parameter validation', () => {
      it.each(curves)(
        'should throw error for wrong alg in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithWrongAlg = { ...jwk, alg: 'ES123' };

          expect(() =>
            weierstrassToRawPublicKeyInternal(
              curve,
              keyByteLength,
              curveName,
              signatureAlgorithm,
              jwkWithWrongAlg as JwkPublicKey,
            ),
          ).toThrow(`Invalid algorithm: ES123, expected ${jwk.alg}`);
        },
      );

      it.each(curves)(
        'should accept null alg in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithNullAlg = {
            ...jwk,
            alg: null,
          } as unknown as JwkPublicKey;

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            jwkWithNullAlg,
          );
          expect(rawPublicKey).toEqual(publicKey);
        },
      );

      it.each(curves)(
        'should accept undefined alg in $curveName JWK',
        ({ createCurve, keyByteLength, curveName, signatureAlgorithm }) => {
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
          const jwkWithUndefinedAlg = {
            ...jwk,
            alg: undefined,
          } as unknown as JwkPublicKey;

          const rawPublicKey = weierstrassToRawPublicKeyInternal(
            curve,
            keyByteLength,
            curveName,
            signatureAlgorithm,
            jwkWithUndefinedAlg,
          );
          expect(rawPublicKey).toEqual(publicKey);
        },
      );
    });
  });
});
