import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import {
  montgomeryToRawPrivateKey,
  montgomeryToRawPrivateKeyInternal,
} from '../montgomeryToRawPrivateKey';
import { montgomeryToJwkPrivateKey } from '../montgomeryToJwkPrivateKey';
import type { JwkPrivateKey } from '../../types';

describe('montgomeryToRawPrivateKey', () => {
  const curve = createX25519(randomBytes);

  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = montgomeryToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });

  describe('error handling', () => {
    describe('d parameter', () => {
      it('should throw an error for missing d parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const { d, ...invalidJwk } = jwk;
        expect(() =>
          montgomeryToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
        ).toThrow('Failed to convert JWK to raw private key');
      });

      it('should throw an error for null d parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: null } as unknown as JwkPrivateKey;
        expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for undefined d parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: undefined } as unknown as JwkPrivateKey;
        expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for empty string d parameter (results in length 0)', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: '' } as JwkPrivateKey;
        expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for non-string d parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: 123 } as unknown as JwkPrivateKey;
        expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for malformed Base64URL in d parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: 'invalid-base64url!' } as JwkPrivateKey;
        expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with invalid length', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(privateKey.length - 1);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for d that does not match public key', () => {
        const privateKey1 = curve.utils.randomPrivateKey();
        const privateKey2 = curve.utils.randomPrivateKey();

        // Create JWK with private key 1 but public key from private key 2
        const jwk = montgomeryToJwkPrivateKey(curve, privateKey1);
        const jwk2 = montgomeryToJwkPrivateKey(curve, privateKey2);
        const jwkWithMismatchedD = {
          ...jwk,
          x: jwk2.x, // Use x from different key
        };

        expect(() =>
          montgomeryToRawPrivateKey(curve, jwkWithMismatchedD as JwkPrivateKey),
        ).toThrow('Failed to convert JWK to raw private key');
      });
    });

    describe('inherited public key validation', () => {
      describe('kty parameter', () => {
        it('should throw an error for missing kty parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const { kty, ...invalidJwk } = jwk;
          expect(() =>
            montgomeryToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null kty parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: null } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for undefined kty parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            kty: undefined,
          } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for invalid kty', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: 'EC' } as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('crv parameter', () => {
        it('should throw an error for missing crv parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const { crv, ...invalidJwk } = jwk;
          expect(() =>
            montgomeryToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null crv parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: null } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for undefined crv parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            crv: undefined,
          } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for invalid crv', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('x parameter', () => {
        it('should throw an error for missing x parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const { x, ...invalidJwk } = jwk;
          expect(() =>
            montgomeryToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null x parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: null } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for undefined x parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            x: undefined,
          } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for empty string x parameter (results in length 0)', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: '' } as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for non-string x parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for malformed Base64URL in x parameter', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            x: 'invalid-base64url!',
          } as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with invalid length', () => {
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(curve.GuBytes.length - 1);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });
    });
  });

  describe('internal function', () => {
    it('should work with internal function', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = montgomeryToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = montgomeryToRawPrivateKeyInternal(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });
});
