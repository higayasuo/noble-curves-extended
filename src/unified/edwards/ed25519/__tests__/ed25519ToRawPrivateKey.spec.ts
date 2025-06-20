import { describe, it, expect } from 'vitest';
import { ed25519ToRawPrivateKey } from '../ed25519ToRawPrivateKey';
import { ed25519ToJwkPrivateKey } from '../ed25519ToJwkPrivateKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('ed25519ToRawPrivateKey', () => {
  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = ed25519ToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });

  describe('kty parameter validation', () => {
    it('should throw an error for missing kty parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const { kty, ...invalidJwk } = jwk;
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for kty',
      );
    });

    it('should throw an error for null kty parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, kty: null };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for kty',
      );
    });

    it('should throw an error for undefined kty parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, kty: undefined };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for kty',
      );
    });

    it('should throw an error for invalid kty', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, kty: 'EC' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported key type',
      );
    });
  });

  describe('crv parameter validation', () => {
    it('should throw an error for missing crv parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const { crv, ...invalidJwk } = jwk;
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for crv',
      );
    });

    it('should throw an error for null crv parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, crv: null };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for crv',
      );
    });

    it('should throw an error for undefined crv parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, crv: undefined };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for crv',
      );
    });

    it('should throw an error for invalid crv', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, crv: 'X25519' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported curve',
      );
    });
  });

  describe('x parameter validation', () => {
    it('should throw an error for missing x parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const { x, ...invalidJwk } = jwk;
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for x',
      );
    });

    it('should throw an error for null x parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, x: null };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for x',
      );
    });

    it('should throw an error for undefined x parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, x: undefined };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for x',
      );
    });

    it('should throw an error for empty string x parameter (results in length 0)', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, x: '' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for x',
      );
    });

    it('should throw an error for non-string x parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, x: 123 };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: invalid parameter type for x',
      );
    });

    it('should throw an error for malformed Base64URL in x parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, x: 'invalid-base64url!' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed encoding for x',
      );
    });
  });

  describe('alg parameter validation', () => {
    it('should throw an error for empty string alg parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, alg: '' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported algorithm',
      );
    });

    it('should throw an error for invalid alg parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, alg: 'ES256' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported algorithm',
      );
    });
  });

  describe('d parameter validation', () => {
    it('should throw an error for missing d parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const { d, ...invalidJwk } = jwk;
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for d',
      );
    });

    it('should throw an error for null d parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, d: null };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for d',
      );
    });

    it('should throw an error for undefined d parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, d: undefined };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: missing required parameter for d',
      );
    });

    it('should throw an error for empty string d parameter (results in length 0)', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, d: '' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for d',
      );
    });

    it('should throw an error for non-string d parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, d: 123 };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
        'Invalid JWK: invalid parameter type for d',
      );
    });

    it('should throw an error for malformed Base64URL in d parameter', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const invalidJwk = { ...jwk, d: 'invalid-base64url!' };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed encoding for d',
      );
    });

    it('should throw an error for invalid private key length (not 32 bytes)', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);

      // Create a 16-byte private key (invalid length)
      const invalidPrivateKey = new Uint8Array(16);
      const invalidJwk = {
        ...jwk,
        d: Buffer.from(invalidPrivateKey).toString('base64url'),
      };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for d',
      );
    });

    it('should throw an error for invalid private key length (64 bytes)', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);

      // Create a 64-byte private key (invalid length for Ed25519)
      const invalidPrivateKey = new Uint8Array(64);
      const invalidJwk = {
        ...jwk,
        d: Buffer.from(invalidPrivateKey).toString('base64url'),
      };
      expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for d',
      );
    });
  });
});
