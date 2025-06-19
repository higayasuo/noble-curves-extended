import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import { x25519ToRawPrivateKey } from '../x25519ToRawPrivateKey';
import { x25519ToJwkPrivateKey } from '../x25519ToJwkPrivateKey';
import type { JwkPrivateKey } from '../../../types';

describe('x25519ToRawPrivateKey', () => {
  describe('successful conversion tests', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = x25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = x25519ToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });

  describe('invalid JWK structure tests', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = x25519ToJwkPrivateKey(curve, privateKey);

    it('should throw an error for invalid kty', () => {
      const invalidJwk = { ...jwk, kty: 'EC' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported key type',
      );
    });

    it('should throw an error for invalid crv', () => {
      const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported curve',
      );
    });

    it('should throw an error for missing x parameter', () => {
      const { x, ...invalidJwk } = jwk;
      expect(() =>
        x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
      ).toThrow('Invalid JWK: missing required parameter for x');
    });

    it('should throw an error for non-string x parameter', () => {
      const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid parameter type for x',
      );
    });

    it('should throw an error for missing d parameter', () => {
      const { d, ...invalidJwk } = jwk;
      expect(() =>
        x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
      ).toThrow('Invalid JWK: missing required parameter for d');
    });

    it('should throw an error for non-string d parameter', () => {
      const invalidJwk = { ...jwk, d: 123 } as unknown as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid parameter type for d',
      );
    });

    it('should throw an error for invalid alg parameter', () => {
      const invalidJwk = { ...jwk, alg: 'ES256' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported algorithm',
      );
    });
  });

  describe('data validation tests', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = x25519ToJwkPrivateKey(curve, privateKey);

    it('should throw an error for malformed Base64URL in x parameter', () => {
      const invalidJwk = { ...jwk, x: 'invalid-base64url!' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed encoding for x',
      );
    });

    it('should throw an error for malformed Base64URL in d parameter', () => {
      const invalidJwk = { ...jwk, d: 'invalid-base64url!' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed encoding for d',
      );
    });

    it('should throw an error for invalid public key', () => {
      const invalidJwk = {
        ...jwk,
        x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      } as JwkPrivateKey; // All zeros
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for x',
      );
    });

    it('should throw an error for invalid private key', () => {
      const invalidJwk = {
        ...jwk,
        d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      } as JwkPrivateKey; // All zeros
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for d',
      );
    });
  });
});
