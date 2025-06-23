import { describe, it, expect, vi } from 'vitest';
import { edwardsSign } from '../edwardsSign';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import tweetnacl from 'tweetnacl';

const message = new TextEncoder().encode('hello');

describe('edwardsSign', () => {
  describe('basic tests', () => {
    it('should sign a message with a valid private key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const signature = edwardsSign(curve, { message, privateKey });
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it('should throw an error when recovered is set to true', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      expect(() =>
        edwardsSign(curve, { message, privateKey, recovered: true }),
      ).toThrow('Recovered signature is not supported');
    });
  });

  describe('compatibility tests', () => {
    describe('tweetnacl compatibility', () => {
      it('should sign a message with a tweetnacl 64-byte private key', () => {
        const curve = createEd25519(randomBytes);
        const tweetnaclKeyPair = tweetnacl.sign.keyPair();
        const privateKey = new Uint8Array(tweetnaclKeyPair.secretKey);
        expect(privateKey.length).toBe(64);

        const signature = edwardsSign(curve, { message, privateKey });
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(64);

        // Verify the signature with tweetnacl
        const isValid = tweetnacl.sign.detached.verify(
          message,
          signature,
          tweetnaclKeyPair.publicKey,
        );
        expect(isValid).toBe(true);
      });
    });

    describe('Web Crypto API compatibility', () => {
      it('should produce a signature that can be verified by Web Crypto API', async () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const signature = edwardsSign(curve, { message, privateKey });

        // Import the public key into Web Crypto API
        const cryptoKey = await crypto.subtle.importKey(
          'raw',
          publicKey,
          { name: 'Ed25519' },
          false,
          ['verify'],
        );

        // Verify the signature
        const isValid = await crypto.subtle.verify(
          { name: 'Ed25519' },
          cryptoKey,
          signature,
          message,
        );

        expect(isValid).toBe(true);
      });
    });
  });

  describe('invalid input tests', () => {
    it('should throw an error for invalid private key length', () => {
      const curve = createEd25519(randomBytes);
      const invalidKey = new Uint8Array(curve.CURVE.nByteLength - 1); // Too short
      expect(() =>
        edwardsSign(curve, { message, privateKey: invalidKey }),
      ).toThrow('Failed to sign message');
    });

    it('should throw an error for null private key', () => {
      const curve = createEd25519(randomBytes);
      expect(() =>
        edwardsSign(curve, { message, privateKey: null as any }),
      ).toThrow('Failed to sign message');
    });

    it('should throw an error for undefined private key', () => {
      const curve = createEd25519(randomBytes);
      expect(() =>
        edwardsSign(curve, { message, privateKey: undefined as any }),
      ).toThrow('Failed to sign message');
    });

    it('should throw an error for null message', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      expect(() =>
        edwardsSign(curve, { message: null as any, privateKey }),
      ).toThrow('Failed to sign message');
    });

    it('should throw an error for undefined message', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      expect(() =>
        edwardsSign(curve, { message: undefined as any, privateKey }),
      ).toThrow('Failed to sign message');
    });
  });

  describe('error handling tests', () => {
    it('should throw a generic error when curve.sign throws an error', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();

      // Mock the curve.sign to throw an error
      const originalSign = curve.sign;
      curve.sign = vi.fn().mockImplementation(() => {
        throw new Error('Internal signing error');
      });

      expect(() => edwardsSign(curve, { message, privateKey })).toThrow(
        'Failed to sign message',
      );

      // Restore the original method
      curve.sign = originalSign;
    });
  });
});
