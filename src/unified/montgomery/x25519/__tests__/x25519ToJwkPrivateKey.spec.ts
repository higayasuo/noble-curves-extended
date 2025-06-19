import { describe, it, expect, vi } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import { x25519ToJwkPrivateKey } from '../x25519ToJwkPrivateKey';
import { decodeBase64Url } from 'u8a-utils';

describe('x25519ToJwkPrivateKey', () => {
  describe('successful conversion tests', () => {
    it('should convert a valid private key to JWK format', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = x25519ToJwkPrivateKey(curve, privateKey);

      // Check JWK structure
      expect(jwk).toEqual({
        kty: 'OKP',
        crv: 'X25519',
        x: expect.any(String),
        d: expect.any(String),
        alg: 'ECDH-ES',
      });

      // Verify that x and d are valid Base64URL strings
      expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(jwk.d).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that x and d decode to 32-byte arrays
      const decodedX = decodeBase64Url(jwk.x);
      const decodedD = decodeBase64Url(jwk.d);
      expect(decodedX.length).toBe(32);
      expect(decodedD.length).toBe(32);

      // Verify that d matches the original private key
      expect(decodedD).toEqual(privateKey);

      // Verify that x matches the public key derived from the private key
      const publicKey = curve.getPublicKey(privateKey);
      expect(decodedX).toEqual(publicKey);
    });

    it('should generate a JWK that can be imported by Web Crypto API', async () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = x25519ToJwkPrivateKey(curve, privateKey);
      const importedKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        {
          name: 'X25519',
        },
        false,
        ['deriveBits', 'deriveKey'],
      );
      expect(importedKey).toBeDefined();
    });
  });

  describe('invalid input tests', () => {
    it('should throw an error for invalid private key length', () => {
      const curve = createX25519(randomBytes);
      const invalidKey = new Uint8Array(16); // Too short
      expect(() => x25519ToJwkPrivateKey(curve, invalidKey)).toThrow(
        'Private key is invalid',
      );
    });

    it('should throw an error for empty private key', () => {
      const curve = createX25519(randomBytes);
      const emptyKey = new Uint8Array(0);
      expect(() => x25519ToJwkPrivateKey(curve, emptyKey)).toThrow(
        'Private key is invalid',
      );
    });

    it('should throw an error for oversized private key', () => {
      const curve = createX25519(randomBytes);
      const oversizedKey = new Uint8Array(64); // Too long
      expect(() => x25519ToJwkPrivateKey(curve, oversizedKey)).toThrow(
        'Private key is invalid',
      );
    });
  });

  describe('error handling tests', () => {
    it('should throw an error when curve.getPublicKey fails', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();

      // Mock getPublicKey to throw an error
      const originalGetPublicKey = curve.getPublicKey;
      curve.getPublicKey = vi.fn().mockImplementation(() => {
        throw new Error('Public key generation failed');
      });

      expect(() => x25519ToJwkPrivateKey(curve, privateKey)).toThrow(
        'Failed to convert private key to JWK',
      );

      // Restore original method
      curve.getPublicKey = originalGetPublicKey;
    });
  });
});
