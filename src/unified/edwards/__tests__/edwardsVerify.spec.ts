import { describe, it, expect, vi } from 'vitest';
import { edwardsVerify } from '../edwardsVerify';
import { edwardsSign } from '../edwardsSign';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { edwardsToJwkPrivateKey } from '../edwardsToJwkPrivateKey';

const message = new TextEncoder().encode('hello');

describe('edwardsVerify', () => {
  describe('compatibility tests', () => {
    it('should verify a valid signature', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const signature = edwardsSign(curve, { message, privateKey });
      expect(edwardsVerify(curve, { signature, message, publicKey })).toBe(
        true,
      );
    });

    it('should verify a signature created by Web Crypto API', async () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwkPrivateKey = edwardsToJwkPrivateKey(curve, privateKey);
      const publicKey = curve.getPublicKey(privateKey);

      // Import the private key into Web Crypto API
      const cryptoPrivateKey = await crypto.subtle.importKey(
        'jwk',
        jwkPrivateKey,
        { name: 'Ed25519' },
        false,
        ['sign'],
      );

      // Sign the message using Web Crypto API
      const signature = new Uint8Array(
        await crypto.subtle.sign(
          { name: 'Ed25519' },
          cryptoPrivateKey,
          message,
        ),
      );

      // Verify the signature using ed25519Verify
      expect(edwardsVerify(curve, { signature, message, publicKey })).toBe(
        true,
      );
    });
  });

  describe('invalid signature tests', () => {
    it('should return false for an invalid signature', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const invalidSignature = new Uint8Array(curve.CURVE.nByteLength * 2); // All zeros
      expect(
        edwardsVerify(curve, {
          signature: invalidSignature,
          message,
          publicKey,
        }),
      ).toBe(false);
    });

    it('should return false for a signature with modified message', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const signature = edwardsSign(curve, { message, privateKey });

      const modifiedMessage = new TextEncoder().encode('hello world');
      expect(
        edwardsVerify(curve, {
          signature,
          message: modifiedMessage,
          publicKey,
        }),
      ).toBe(false);
    });

    it('should return false for a signature with wrong public key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey1 = curve.utils.randomPrivateKey();
      const privateKey2 = curve.utils.randomPrivateKey();
      const publicKey2 = curve.getPublicKey(privateKey2);
      const signature = edwardsSign(curve, {
        message,
        privateKey: privateKey1,
      });

      expect(
        edwardsVerify(curve, { signature, message, publicKey: publicKey2 }),
      ).toBe(false);
    });
  });

  describe('error handling tests', () => {
    it('should return false for an invalid public key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = new Uint8Array(32); // All zeros (invalid)
      const signature = edwardsSign(curve, { message, privateKey });
      expect(edwardsVerify(curve, { signature, message, publicKey })).toBe(
        false,
      );
    });

    it('should return false when curve.verify throws an error', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const signature = edwardsSign(curve, { message, privateKey });

      // Mock the curve.verify to throw an error
      const originalVerify = curve.verify;
      curve.verify = vi.fn().mockImplementation(() => {
        throw new Error('Internal verification error');
      });

      expect(edwardsVerify(curve, { signature, message, publicKey })).toBe(
        false,
      );

      // Restore the original method
      curve.verify = originalVerify;
    });
  });
});
