import { describe, it, expect } from 'vitest';
import { createP256, createP384, createP521 } from '../nist';
import { p256 as nobleP256 } from '@noble/curves/p256';
import { p384 as nobleP384 } from '@noble/curves/p384';
import { p521 as nobleP521 } from '@noble/curves/p521';
import { randomBytes } from '@noble/hashes/utils';

describe('nist', () => {
  describe('P256', () => {
    const customP256 = createP256(randomBytes);

    it('should verify signature created by noble-curves p256', () => {
      // Generate key pair using noble-curves
      const privateKey = nobleP256.utils.randomPrivateKey();
      const publicKey = nobleP256.getPublicKey(privateKey);

      // Create message and signature using noble-curves
      const message = new TextEncoder().encode('test message');
      const nobleMessage = Uint8Array.from(message);
      const signature = nobleP256.sign(nobleMessage, privateKey);

      // Verify using our custom implementation
      const isValid = customP256.verify(signature, message, publicKey);
      expect(isValid).toBe(true);
    });

    it('should be verified by noble-curves p256', () => {
      // Generate key pair using our custom implementation
      const privateKey = customP256.utils.randomPrivateKey();
      const publicKey = customP256.getPublicKey(privateKey);

      // Create message and signature using our custom implementation
      const message = new TextEncoder().encode('test message');
      const nobleMessage = Uint8Array.from(message);
      const signature = customP256.sign(message, privateKey);

      // Verify using noble-curves
      const isValid = nobleP256.verify(signature, nobleMessage, publicKey);
      expect(isValid).toBe(true);
    });
  });

  describe('P384', () => {
    const customP384 = createP384(randomBytes);

    it('should verify signature created by noble-curves p384', () => {
      // Generate key pair using noble-curves
      const privateKey = nobleP384.utils.randomPrivateKey();
      const publicKey = nobleP384.getPublicKey(privateKey);

      // Create message and signature using noble-curves
      const message = new TextEncoder().encode('test message');
      const nobleMessage = Uint8Array.from(message);
      const signature = nobleP384.sign(nobleMessage, privateKey);

      // Verify using our custom implementation
      const isValid = customP384.verify(signature, message, publicKey);
      expect(isValid).toBe(true);
    });

    it('should be verified by noble-curves p384', () => {
      // Generate key pair using our custom implementation
      const privateKey = customP384.utils.randomPrivateKey();
      const publicKey = customP384.getPublicKey(privateKey);

      // Create message and signature using our custom implementation
      const message = new TextEncoder().encode('test message');
      const nobleMessage = Uint8Array.from(message);
      const signature = customP384.sign(message, privateKey);

      // Verify using noble-curves
      const isValid = nobleP384.verify(signature, nobleMessage, publicKey);
      expect(isValid).toBe(true);
    });
  });

  describe('P521', () => {
    const customP521 = createP521(randomBytes);

    it('should verify signature created by noble-curves p521', () => {
      // Generate key pair using noble-curves
      const privateKey = nobleP521.utils.randomPrivateKey();
      const publicKey = nobleP521.getPublicKey(privateKey);

      // Create message and signature using noble-curves
      const message = new TextEncoder().encode('test message');
      const nobleMessage = Uint8Array.from(message);
      const signature = nobleP521.sign(nobleMessage, privateKey);

      // Verify using our custom implementation
      const isValid = customP521.verify(signature, message, publicKey);
      expect(isValid).toBe(true);
    });

    it('should be verified by noble-curves p521', () => {
      // Generate key pair using our custom implementation
      const privateKey = customP521.utils.randomPrivateKey();
      const publicKey = customP521.getPublicKey(privateKey);

      // Create message and signature using our custom implementation
      const message = new TextEncoder().encode('test message');
      const nobleMessage = Uint8Array.from(message);
      const signature = customP521.sign(message, privateKey);

      // Verify using noble-curves
      const isValid = nobleP521.verify(signature, nobleMessage, publicKey);
      expect(isValid).toBe(true);
    });
  });
});
