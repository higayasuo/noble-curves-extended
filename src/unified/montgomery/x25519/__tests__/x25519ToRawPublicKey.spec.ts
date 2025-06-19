import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import { x25519ToRawPublicKey } from '../x25519ToRawPublicKey';
import { x25519ToJwkPublicKey } from '../x25519ToJwkPublicKey';
import type { JwkPublicKey } from '../../../types';

describe('x25519ToRawPublicKey', () => {
  describe('successful conversion tests', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const rawPublicKey = x25519ToRawPublicKey(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });
  });

  describe('invalid JWK structure tests', () => {
    it('should throw an error for invalid kty', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const invalidJwk = { ...jwk, kty: 'EC' } as JwkPublicKey;
      expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported key type',
      );
    });

    it('should throw an error for invalid crv', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPublicKey;
      expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported curve',
      );
    });

    it('should throw an error for missing x parameter', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const { x, ...invalidJwk } = jwk;
      expect(() =>
        x25519ToRawPublicKey(curve, invalidJwk as JwkPublicKey),
      ).toThrow('Invalid JWK: missing required parameter for x');
    });

    it('should throw an error for non-string x parameter', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPublicKey;
      expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid parameter type for x',
      );
    });

    it('should throw an error for invalid alg parameter', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const invalidJwk = { ...jwk, alg: 'ES256' } as JwkPublicKey;
      expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: unsupported algorithm',
      );
    });
  });

  describe('data validation tests', () => {
    it('should throw an error for malformed Base64URL in x parameter', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const invalidJwk = { ...jwk, x: 'invalid-base64url!' } as JwkPublicKey;
      expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed encoding for x',
      );
    });

    it('should throw an error for invalid public key', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = x25519ToJwkPublicKey(curve, publicKey);
      const invalidJwk = {
        ...jwk,
        x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      } as JwkPublicKey; // All zeros
      expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: invalid key data for x',
      );
    });
  });
});
