import { describe, expect, it } from 'vitest';
import { ed25519GetPublicKey } from '../ed25519GetPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import tweetnacl from 'tweetnacl';

describe('ed25519GetPublicKey', () => {
  describe('valid private keys', () => {
    it('should generate a valid public key from a valid private key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = ed25519GetPublicKey(curve, privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);
    });

    it('should generate a valid public key from a tweetnacl 64-byte private key', () => {
      const curve = createEd25519(randomBytes);
      const tweetnaclKeyPair = tweetnacl.sign.keyPair();
      const privateKey = new Uint8Array(tweetnaclKeyPair.secretKey);
      expect(privateKey.length).toBe(64);

      const publicKey = ed25519GetPublicKey(curve, privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);

      // Verify that the generated public key matches tweetnacl's public key
      expect(publicKey).toEqual(tweetnaclKeyPair.publicKey);
    });

    it('should generate different public keys for different private keys', () => {
      const curve = createEd25519(randomBytes);
      const privateKey1 = curve.utils.randomPrivateKey();
      const privateKey2 = curve.utils.randomPrivateKey();

      const publicKey1 = ed25519GetPublicKey(curve, privateKey1);
      const publicKey2 = ed25519GetPublicKey(curve, privateKey2);

      expect(publicKey1).not.toEqual(publicKey2);
    });
  });

  describe('invalid private key lengths', () => {
    it('should throw an error for private key with length 0', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(0);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length 16', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(16);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length 31', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(31);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length 33', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(33);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length 63', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(63);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length 65', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(65);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length 128', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(128);
      expect(() => ed25519GetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });
  });

  describe('invalid 64-byte private keys', () => {
    it('should throw an error for invalid embedded public key in 64-byte private key', () => {
      const curve = createEd25519(randomBytes);
      const seed = new Uint8Array(32);
      // Fill with random bytes (not all zeros)
      for (let i = 0; i < 32; i++) {
        seed[i] = Math.floor(Math.random() * 256);
      }

      // Create a 64-byte private key with invalid embedded public key
      const invalidPrivateKey = new Uint8Array(64);
      invalidPrivateKey.set(seed, 0);
      // Set the embedded public key to all zeros (invalid)
      invalidPrivateKey.fill(0, 32);

      expect(() => ed25519GetPublicKey(curve, invalidPrivateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error when embedded public key does not match calculated public key', () => {
      const curve = createEd25519(randomBytes);

      // Create a valid seed
      const seed = curve.utils.randomPrivateKey();

      // Calculate the correct public key from the seed
      const correctPublicKey = curve.getPublicKey(seed);

      // Create a 64-byte private key with a different embedded public key
      const invalidPrivateKey = new Uint8Array(64);
      invalidPrivateKey.set(seed, 0);

      // Set a different public key in the embedded part (flip some bits)
      const wrongPublicKey = new Uint8Array(correctPublicKey);
      wrongPublicKey[0] ^= 0xff; // Flip all bits of the first byte
      invalidPrivateKey.set(wrongPublicKey, 32);

      expect(() => ed25519GetPublicKey(curve, invalidPrivateKey)).toThrow(
        'Failed to get public key',
      );
    });
  });

  describe('compression options', () => {
    it('should throw an error for uncompressed public keys', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      expect(() => ed25519GetPublicKey(curve, privateKey, false)).toThrow(
        'Uncompressed public key is not supported',
      );
    });
  });
});
