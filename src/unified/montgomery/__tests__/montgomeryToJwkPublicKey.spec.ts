import { describe, it, expect } from 'vitest';
import { montgomeryToJwkPublicKey } from '../montgomeryToJwkPublicKey';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';

describe('montgomeryToJwkPublicKey', () => {
  const curve = createX25519(randomBytes);

  // Test vectors from RFC 7748
  const publicKey = new Uint8Array([
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc,
    0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x61, 0x3a, 0xbe,
    0x29, 0xed, 0xa9, 0x00, 0x0a, 0x45, 0xbe, 0x0b,
  ]);

  describe('successful conversion tests', () => {
    it('should convert a valid public key to JWK format', () => {
      const jwk = montgomeryToJwkPublicKey(curve, publicKey);

      expect(jwk).toEqual({
        kty: 'OKP',
        crv: 'X25519',
        x: 'hSDwCYkwp1R0i33ctD73Wg2_Og0mYTq-Ke2pAApFvgs',
      });
    });

    it('should generate a JWK that can be imported by Web Crypto API', async () => {
      const jwk = montgomeryToJwkPublicKey(curve, publicKey);
      const importedKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        {
          name: 'X25519',
        },
        false,
        [],
      );
      expect(importedKey).toBeDefined();
    });
  });

  describe('invalid input tests', () => {
    it('should throw an error for invalid public key length', () => {
      const invalidKey = new Uint8Array(curve.GuBytes.length - 1); // Too short
      expect(() => montgomeryToJwkPublicKey(curve, invalidKey)).toThrow(
        'Failed to convert public key to JWK',
      );
    });

    it('should throw an error for empty public key', () => {
      const emptyKey = new Uint8Array(0);
      expect(() => montgomeryToJwkPublicKey(curve, emptyKey)).toThrow(
        'Failed to convert public key to JWK',
      );
    });

    it('should throw an error for oversized public key', () => {
      const oversizedKey = new Uint8Array(curve.GuBytes.length + 1); // Too long
      expect(() => montgomeryToJwkPublicKey(curve, oversizedKey)).toThrow(
        'Failed to convert public key to JWK',
      );
    });
  });
});
