import { describe, it, expect } from 'vitest';
import { createX25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { x25519ToRawPrivateKey } from '../x25519ToRawPrivateKey';
import { x25519ToJwkPrivateKey } from '../x25519ToJwkPrivateKey';
import type { JwkPrivateKey } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519ToRawPrivateKey', () => {
  describe('successful cases', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = x25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = x25519ToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });

  describe('error cases', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = x25519ToJwkPrivateKey(curve, privateKey);

    it('should throw an error for invalid kty', () => {
      const invalidJwk = { ...jwk, kty: 'EC' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: kty parameter must be OKP',
      );
    });

    it('should throw an error for invalid crv', () => {
      const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: crv parameter must be X25519',
      );
    });

    it('should throw an error for missing x parameter', () => {
      const { x, ...invalidJwk } = jwk;
      expect(() =>
        x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
      ).toThrow('Invalid JWK: x parameter is missing');
    });

    it('should throw an error for non-string x parameter', () => {
      const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: x parameter must be a string',
      );
    });

    it('should throw an error for missing d parameter', () => {
      const { d, ...invalidJwk } = jwk;
      expect(() =>
        x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
      ).toThrow('Invalid JWK: d parameter is missing');
    });

    it('should throw an error for non-string d parameter', () => {
      const invalidJwk = { ...jwk, d: 123 } as unknown as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: d parameter must be a string',
      );
    });

    it('should throw an error for invalid alg parameter', () => {
      const invalidJwk = { ...jwk, alg: 'ES256' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: alg parameter must be ECDH-ES',
      );
    });

    it('should throw an error for malformed Base64URL in x parameter', () => {
      const invalidJwk = { ...jwk, x: 'invalid-base64url!' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed Base64URL in x parameter',
      );
    });

    it('should throw an error for malformed Base64URL in d parameter', () => {
      const invalidJwk = { ...jwk, d: 'invalid-base64url!' } as JwkPrivateKey;
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid JWK: malformed Base64URL in d parameter',
      );
    });

    it('should throw an error for invalid public key', () => {
      const invalidJwk = {
        ...jwk,
        x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      } as JwkPrivateKey; // All zeros
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid X25519 public key',
      );
    });

    it('should throw an error for invalid private key', () => {
      const invalidJwk = {
        ...jwk,
        d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      } as JwkPrivateKey; // All zeros
      expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Invalid X25519 private key',
      );
    });
  });
});
