import { describe, it, expect, vi } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import { montgomeryToJwkPrivateKey } from '../montgomeryToJwkPrivateKey';
import { decodeBase64Url } from 'u8a-utils';

describe('montgomeryToJwkPrivateKey', () => {
  const curve = createX25519(randomBytes);

  describe('successful conversion tests', () => {
    it('should convert a valid private key to JWK format', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);

      // Check JWK structure
      expect(jwk).toEqual({
        kty: 'OKP',
        crv: 'X25519',
        x: expect.any(String),
        d: expect.any(String),
      });

      // Verify that x and d are valid Base64URL strings
      expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(jwk.d).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify that x and d decode to correct length arrays
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
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
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
      const invalidKey = new Uint8Array(32 - 1); // Too short
      expect(() =>
        montgomeryToJwkPrivateKey(curve, 32, 'X25519', invalidKey),
      ).toThrow('Failed to convert private key to JWK');
    });

    it('should throw an error for empty private key', () => {
      const emptyKey = new Uint8Array(0);
      expect(() =>
        montgomeryToJwkPrivateKey(curve, 32, 'X25519', emptyKey),
      ).toThrow('Failed to convert private key to JWK');
    });

    it('should throw an error for oversized private key', () => {
      const oversizedKey = new Uint8Array(32 + 1); // Too long
      expect(() =>
        montgomeryToJwkPrivateKey(curve, 32, 'X25519', oversizedKey),
      ).toThrow('Failed to convert private key to JWK');
    });
  });

  describe('error handling tests', () => {
    it('should throw an error when curve.getPublicKey fails', () => {
      const privateKey = curve.utils.randomPrivateKey();

      // Mock getPublicKey to throw an error
      const originalGetPublicKey = curve.getPublicKey;
      curve.getPublicKey = vi.fn().mockImplementation(() => {
        throw new Error('Public key generation failed');
      });

      expect(() =>
        montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey),
      ).toThrow('Failed to convert private key to JWK');

      // Restore original method
      curve.getPublicKey = originalGetPublicKey;
    });
  });
});
