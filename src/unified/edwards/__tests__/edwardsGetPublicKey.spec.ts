import { describe, expect, it } from 'vitest';
import { edwardsGetPublicKey } from '../edwardsGetPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import tweetnacl from 'tweetnacl';

describe('edwardsGetPublicKey', () => {
  describe('valid private keys', () => {
    it('should generate a valid public key from a valid private key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = edwardsGetPublicKey(curve, privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);
    });

    it('should generate a valid public key from a tweetnacl 64-byte private key', () => {
      const curve = createEd25519(randomBytes);
      const tweetnaclKeyPair = tweetnacl.sign.keyPair();
      const privateKey = new Uint8Array(tweetnaclKeyPair.secretKey);
      expect(privateKey.length).toBe(64);

      const publicKey = edwardsGetPublicKey(curve, privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);

      // Verify that the generated public key matches tweetnacl's public key
      expect(publicKey).toEqual(tweetnaclKeyPair.publicKey);
    });

    it('should generate different public keys for different private keys', () => {
      const curve = createEd25519(randomBytes);
      const privateKey1 = curve.utils.randomPrivateKey();
      const privateKey2 = curve.utils.randomPrivateKey();

      const publicKey1 = edwardsGetPublicKey(curve, privateKey1);
      const publicKey2 = edwardsGetPublicKey(curve, privateKey2);

      expect(publicKey1).not.toEqual(publicKey2);
    });
  });

  describe('invalid private key lengths', () => {
    it('should throw an error for private key with length 0', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(0);
      expect(() => edwardsGetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length less than required', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(curve.CURVE.nByteLength - 1);
      expect(() => edwardsGetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });

    it('should throw an error for private key with length more than required', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = new Uint8Array(curve.CURVE.nByteLength + 1);
      expect(() => edwardsGetPublicKey(curve, privateKey)).toThrow(
        'Failed to get public key',
      );
    });
  });

  describe('compression options', () => {
    it('should throw an error for uncompressed public keys', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      expect(() => edwardsGetPublicKey(curve, privateKey, false)).toThrow(
        'Uncompressed public key is not supported',
      );
    });
  });
});
