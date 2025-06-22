import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import {
  x25519ToRawPublicKey,
  x25519ToRawPublicKeyInternal,
} from '../x25519ToRawPublicKey';
import { x25519ToJwkPublicKey } from '../x25519ToJwkPublicKey';
import type { JwkPublicKey } from '../../../types';

describe('x25519ToRawPublicKey', () => {
  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const rawPublicKey = x25519ToRawPublicKey(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });

  describe('error handling', () => {
    describe('kty parameter', () => {
      it('should throw an error for missing kty parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const { kty, ...invalidJwk } = jwk;
        expect(() =>
          x25519ToRawPublicKey(curve, invalidJwk as JwkPublicKey),
        ).toThrow('Failed to convert JWK to raw public key');
      });

      it('should throw an error for null kty parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: null } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined kty parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = {
          ...jwk,
          kty: undefined,
        } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid kty', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, kty: 'EC' } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('crv parameter', () => {
      it('should throw an error for missing crv parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const { crv, ...invalidJwk } = jwk;
        expect(() =>
          x25519ToRawPublicKey(curve, invalidJwk as JwkPublicKey),
        ).toThrow('Failed to convert JWK to raw public key');
      });

      it('should throw an error for null crv parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: null } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined crv parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = {
          ...jwk,
          crv: undefined,
        } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for invalid crv', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });

    describe('x parameter', () => {
      it('should throw an error for missing x parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const { x, ...invalidJwk } = jwk;
        expect(() =>
          x25519ToRawPublicKey(curve, invalidJwk as JwkPublicKey),
        ).toThrow('Failed to convert JWK to raw public key');
      });

      it('should throw an error for null x parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: null } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for undefined x parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: undefined } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for empty string x parameter (results in length 0)', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: '' } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for non-string x parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for malformed Base64URL in x parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = x25519ToJwkPublicKey(curve, publicKey);
        const invalidJwk = { ...jwk, x: 'invalid-base64url!' } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 16', () => {
        const curve = createX25519(randomBytes);
        const invalidPublicKey = new Uint8Array(16);
        const jwk = x25519ToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 31', () => {
        const curve = createX25519(randomBytes);
        const invalidPublicKey = new Uint8Array(31);
        const jwk = x25519ToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 33', () => {
        const curve = createX25519(randomBytes);
        const invalidPublicKey = new Uint8Array(33);
        const jwk = x25519ToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 48', () => {
        const curve = createX25519(randomBytes);
        const invalidPublicKey = new Uint8Array(48);
        const jwk = x25519ToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 64', () => {
        const curve = createX25519(randomBytes);
        const invalidPublicKey = new Uint8Array(64);
        const jwk = x25519ToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });

      it('should throw an error for public key with length 128', () => {
        const curve = createX25519(randomBytes);
        const invalidPublicKey = new Uint8Array(128);
        const jwk = x25519ToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const invalidJwk = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw public key',
        );
      });
    });
  });

  describe('internal function', () => {
    it('should work with internal function', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const rawPublicKey = x25519ToRawPublicKeyInternal(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });
});
