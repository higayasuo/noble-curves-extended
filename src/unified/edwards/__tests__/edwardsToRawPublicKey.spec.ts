import { describe, it, expect } from 'vitest';
import {
  edwardsToRawPublicKey,
  edwardsToRawPublicKeyInternal,
} from '../edwardsToRawPublicKey';
import { edwardsToJwkPublicKey } from '../edwardsToJwkPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('edwardsToRawPublicKey', () => {
  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = edwardsToJwkPublicKey(curve, publicKey);
      const rawPublicKey = edwardsToRawPublicKey(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });

  describe('error handling', () => {
    describe('kty parameter', () => {
      it('should throw an error for missing kty parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { kty, ...invalidJwk } = jwk;
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for null kty parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: null };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined kty parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: undefined };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: 'EC' };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('crv parameter', () => {
      it('should throw an error for missing crv parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { crv, ...invalidJwk } = jwk;
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for null crv parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: null };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined crv parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: undefined };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: 'X25519' };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('x parameter', () => {
      it('should throw an error for missing x parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { x, ...invalidJwk } = jwk;
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for null x parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: null };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined x parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: undefined };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for empty string x parameter (results in length 0)', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: '' };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for non-string x parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: 123 };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for malformed Base64URL in x parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: 'invalid-base64url!' };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 16', () => {
        const curve = createEd25519(randomBytes);
        const invalidPublicKey = new Uint8Array(16);
        const jwk = edwardsToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 31', () => {
        const curve = createEd25519(randomBytes);
        const invalidPublicKey = new Uint8Array(31);
        const jwk = edwardsToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 33', () => {
        const curve = createEd25519(randomBytes);
        const invalidPublicKey = new Uint8Array(33);
        const jwk = edwardsToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 64', () => {
        const curve = createEd25519(randomBytes);
        const invalidPublicKey = new Uint8Array(64);
        const jwk = edwardsToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 128', () => {
        const curve = createEd25519(randomBytes);
        const invalidPublicKey = new Uint8Array(128);
        const jwk = edwardsToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('alg parameter', () => {
      it('should throw an error for empty string alg parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, alg: '' };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid alg parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, alg: 'ES256' };
        expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });
  });

  describe('internal function', () => {
    it('should work with internal function', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = edwardsToJwkPublicKey(curve, publicKey);
      const rawPublicKey = edwardsToRawPublicKeyInternal(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });
});
