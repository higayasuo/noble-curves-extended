import { describe, it, expect, vi } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import { montgomeryGetSharedSecret } from '../montgomeryGetSharedSecret';
import { montgomeryToJwkPrivateKey } from '../montgomeryToJwkPrivateKey';
import { montgomeryToJwkPublicKey } from '../montgomeryToJwkPublicKey';
import { decodeHex } from 'u8a-utils';

describe('montgomeryGetSharedSecret', () => {
  const curve = createX25519(randomBytes);

  describe('compatibility tests', () => {
    it('should compute the same shared secret for both parties', () => {
      const alicePrivateKey = curve.utils.randomPrivateKey();
      const alicePublicKey = curve.getPublicKey(alicePrivateKey);
      const bobPrivateKey = curve.utils.randomPrivateKey();
      const bobPublicKey = curve.getPublicKey(bobPrivateKey);

      const aliceSharedSecret = montgomeryGetSharedSecret(curve, {
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey,
      });
      const bobSharedSecret = montgomeryGetSharedSecret(curve, {
        privateKey: bobPrivateKey,
        publicKey: alicePublicKey,
      });

      expect(aliceSharedSecret).toEqual(bobSharedSecret);
    });

    it('should match Web Crypto API deriveBits result', async () => {
      const alicePrivateKey = curve.utils.randomPrivateKey();
      const bobPrivateKey = curve.utils.randomPrivateKey();
      const bobPublicKey = curve.getPublicKey(bobPrivateKey);

      // Convert keys to JWK format
      const aliceJwkPrivateKey = montgomeryToJwkPrivateKey(
        curve,
        32,
        'X25519',
        alicePrivateKey,
      );
      const bobJwkPublicKey = montgomeryToJwkPublicKey(
        curve,
        32,
        'X25519',
        bobPublicKey,
      );

      // Import keys using Web Crypto API
      const aliceCryptoKey = await crypto.subtle.importKey(
        'jwk',
        aliceJwkPrivateKey,
        {
          name: 'X25519',
        },
        false,
        ['deriveBits'],
      );

      const bobCryptoKey = await crypto.subtle.importKey(
        'jwk',
        bobJwkPublicKey,
        {
          name: 'X25519',
        },
        false,
        [],
      );

      // Derive shared secret using Web Crypto API
      const webCryptoSharedSecret = new Uint8Array(
        await crypto.subtle.deriveBits(
          {
            name: 'X25519',
            public: bobCryptoKey,
          },
          aliceCryptoKey,
          256,
        ),
      );

      // Derive shared secret using montgomeryGetSharedSecret
      const x25519SharedSecret = montgomeryGetSharedSecret(curve, {
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey,
      });

      // Compare results
      expect(x25519SharedSecret).toEqual(webCryptoSharedSecret);
    });
  });

  describe('security tests', () => {
    it('should throw an error for RFC 7748 §6.1 small order points', () => {
      const privateKey = curve.utils.randomPrivateKey();

      // RFC 7748 §6.1 small order points
      const smallOrderPoints = [
        // 0 (order 1)
        '0000000000000000000000000000000000000000000000000000000000000000',
        // 1 (order 1)
        '0100000000000000000000000000000000000000000000000000000000000000',
        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
        // p-1 (order 2)
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
        // p (order 4)
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
        // p+1 (order 1)
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee',
      ].map((hex) => decodeHex(hex));

      for (const smallOrderPoint of smallOrderPoints) {
        expect(() =>
          montgomeryGetSharedSecret(curve, {
            privateKey,
            publicKey: smallOrderPoint,
          }),
        ).toThrow('Failed to compute shared secret');
      }
    });

    it('should throw a generic error when curve.getSharedSecret returns all zeros', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(curve.utils.randomPrivateKey());

      // Mock the curve.getSharedSecret to return all zeros
      const originalGetSharedSecret = curve.getSharedSecret;
      curve.getSharedSecret = vi.fn().mockReturnValue(new Uint8Array(32));

      expect(() =>
        montgomeryGetSharedSecret(curve, {
          privateKey,
          publicKey,
        }),
      ).toThrow('Failed to compute shared secret');

      // Restore the original method
      curve.getSharedSecret = originalGetSharedSecret;
    });
  });

  describe('invalid input tests', () => {
    it('should throw an error for private key with wrong length', () => {
      const invalidPrivateKey = new Uint8Array(32 - 1); // Wrong length
      const publicKey = curve.getPublicKey(curve.utils.randomPrivateKey());

      expect(() =>
        montgomeryGetSharedSecret(curve, {
          privateKey: invalidPrivateKey,
          publicKey,
        }),
      ).toThrow('Failed to compute shared secret');
    });

    it('should throw an error for public key with wrong length', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const invalidPublicKey = new Uint8Array(32 - 1); // Wrong length

      expect(() =>
        montgomeryGetSharedSecret(curve, {
          privateKey,
          publicKey: invalidPublicKey,
        }),
      ).toThrow('Failed to compute shared secret');
    });
  });

  describe('error handling tests', () => {
    it('should throw a generic error when curve.getSharedSecret throws an error', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(curve.utils.randomPrivateKey());

      // Mock the curve.getSharedSecret to throw an error
      const originalGetSharedSecret = curve.getSharedSecret;
      curve.getSharedSecret = vi.fn().mockImplementation(() => {
        throw new Error('Internal shared secret error');
      });

      expect(() =>
        montgomeryGetSharedSecret(curve, {
          privateKey,
          publicKey,
        }),
      ).toThrow('Failed to compute shared secret');

      // Restore the original method
      curve.getSharedSecret = originalGetSharedSecret;
    });
  });
});
