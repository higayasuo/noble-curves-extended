import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import {
  montgomeryToRawPublicKey,
  montgomeryToRawPublicKeyInternal,
} from '../montgomeryToRawPublicKey';
import { montgomeryToJwkPublicKey } from '../montgomeryToJwkPublicKey';
import type { JwkPublicKey } from '../../types';

describe('montgomeryToRawPublicKey', () => {
  const curve = createX25519(randomBytes);

  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = montgomeryToJwkPublicKey(curve, publicKey);
      const rawPublicKey = montgomeryToRawPublicKey(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });

  describe('error handling', () => {
    describe('kty parameter', () => {
      it('should throw an error for missing kty parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const { kty, ...invalidJwk } = jwk;
        expect(() =>
          montgomeryToRawPublicKey(curve, invalidJwk as JwkPublicKey),
        ).toThrow('Failed to convert JWK to raw public key');
      });

      it('should throw an error for null kty parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: null } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined kty parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = {
          ...jwk,
          kty: undefined,
        } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: 'EC' } as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('crv parameter', () => {
      it('should throw an error for missing crv parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const { crv, ...invalidJwk } = jwk;
        expect(() =>
          montgomeryToRawPublicKey(curve, invalidJwk as JwkPublicKey),
        ).toThrow('Failed to convert JWK to raw public key');
      });

      it('should throw an error for null crv parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: null } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined crv parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = {
          ...jwk,
          crv: undefined,
        } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('x parameter', () => {
      it('should throw an error for missing x parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const { x, ...invalidJwk } = jwk;
        expect(() =>
          montgomeryToRawPublicKey(curve, invalidJwk as JwkPublicKey),
        ).toThrow('Failed to convert JWK to raw public key');
      });

      it('should throw an error for null x parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: null } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined x parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: undefined } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for empty string x parameter (results in length 0)', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: '' } as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for non-string x parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for malformed Base64URL in x parameter', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: 'invalid-base64url!' } as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with invalidlength', () => {
        const invalidPublicKey = new Uint8Array(curve.GuBytes.length - 1);
        const jwk = montgomeryToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });
  });

  describe('internal function', () => {
    it('should work with internal function', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = montgomeryToJwkPublicKey(curve, publicKey);
      const rawPublicKey = montgomeryToRawPublicKeyInternal(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });
});
