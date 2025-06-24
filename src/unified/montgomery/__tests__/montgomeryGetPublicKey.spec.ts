import { describe, expect, it, vi } from 'vitest';
import { montgomeryGetPublicKey } from '../montgomeryGetPublicKey';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';

describe('montgomeryGetPublicKey', () => {
  const curve = createX25519(randomBytes);

  describe('valid private keys', () => {
    it('should generate a valid public key from a valid private key', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = montgomeryGetPublicKey(curve, privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(curve.GuBytes.length);
    });

    it('should generate different public keys for different private keys', () => {
      const privateKey1 = curve.utils.randomPrivateKey();
      const privateKey2 = curve.utils.randomPrivateKey();

      const publicKey1 = montgomeryGetPublicKey(curve, privateKey1);
      const publicKey2 = montgomeryGetPublicKey(curve, privateKey2);

      expect(publicKey1).not.toEqual(publicKey2);
    });
  });

  describe('invalid private key lengths', () => {
    it('should throw an error for invalid private key length', () => {
      const privateKey = new Uint8Array(curve.GuBytes.length - 1);
      expect(() => montgomeryGetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });
  });

  describe('compression options', () => {
    it('should throw an error for uncompressed public keys', () => {
      const privateKey = curve.utils.randomPrivateKey();
      expect(() => montgomeryGetPublicKey(curve, privateKey, false)).toThrow(
        'Uncompressed public key is not supported',
      );
    });
  });

  describe('error handling', () => {
    it('should throw a generic error when curve.getPublicKey throws an error', () => {
      const privateKey = curve.utils.randomPrivateKey();

      const originalGetPublicKey = curve.getPublicKey;
      curve.getPublicKey = vi.fn().mockImplementation(() => {
        throw new Error('Internal curve error');
      });

      expect(() => montgomeryGetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );

      // Restore the original method
      curve.getPublicKey = originalGetPublicKey;
    });
  });
});
