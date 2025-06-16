import { describe, it, expect } from 'vitest';
import { createX25519 } from '../../../x25519/x25519';
import type { RandomBytes } from '../../../types';
import { X25519 } from '../X25519';
import type { CurveFn } from '@noble/curves/abstract/montgomery';
import { randomBytes as cryptoRandomBytes } from 'crypto';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('X25519', () => {
  const curve = createX25519(randomBytes);
  const x25519 = new X25519(curve, randomBytes);

  it('should have correct curve and algorithm identifiers', () => {
    expect(x25519.crv).toBe('X25519');
    expect(x25519.alg).toBe('ECDH-ES');
  });

  describe('getCurve', () => {
    it('should return the same curve instance passed to the constructor', () => {
      // Default type
      expect(x25519.getCurve()).toBe(curve);
      // Explicit type
      const returned = x25519.getCurve<CurveFn>();
      expect(returned).toBe(curve);
    });
  });

  describe('randomPrivateKey', () => {
    it('should generate a valid private key', () => {
      const privateKey = x25519.randomPrivateKey();
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);
      expect(x25519.isValidPrivateKey(privateKey)).toBe(true);
    });
  });

  describe('getPublicKey', () => {
    it('should generate a valid public key from a private key', () => {
      const privateKey = x25519.randomPrivateKey();
      const publicKey = x25519.getPublicKey(privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);
      expect(x25519.isValidPublicKey(publicKey)).toBe(true);
    });
    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      expect(() => x25519.getPublicKey(invalidPrivateKey)).toThrow(
        'X25519 private key is invalid',
      );
    });
  });

  describe('toJwkPrivateKey', () => {
    it('should convert a private key to JWK format', () => {
      const privateKey = x25519.randomPrivateKey();
      const jwk = x25519.toJwkPrivateKey(privateKey);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'X25519');
      expect(jwk).toHaveProperty('d');
      expect(jwk).toHaveProperty('x');
    });
    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      expect(() => x25519.toJwkPrivateKey(invalidPrivateKey)).toThrow(
        'Invalid X25519 private key',
      );
    });
  });

  describe('toJwkPublicKey', () => {
    it('should convert a public key to JWK format', () => {
      const privateKey = x25519.randomPrivateKey();
      const publicKey = x25519.getPublicKey(privateKey);
      const jwk = x25519.toJwkPublicKey(publicKey);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'X25519');
      expect(jwk).toHaveProperty('x');
    });
    it('should throw an error for invalid public key', () => {
      const invalidPublicKey = new Uint8Array(32); // All zeros
      expect(() => x25519.toJwkPublicKey(invalidPublicKey)).toThrow(
        'Invalid X25519 public key',
      );
    });
  });

  describe('toRawPrivateKey', () => {
    it('should convert a JWK to a raw private key', () => {
      const privateKey = x25519.randomPrivateKey();
      const jwk = x25519.toJwkPrivateKey(privateKey);
      const rawPrivateKey = x25519.toRawPrivateKey(jwk);
      expect(rawPrivateKey).toBeInstanceOf(Uint8Array);
      expect(rawPrivateKey.length).toBe(32);
      expect(rawPrivateKey).toEqual(privateKey);
    });
    it('should throw an error for invalid JWK', () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'X25519',
        d: 'invalid-base64url!',
        x: 'hSDwCYkwp1R0i33ctD73Wg2_Og0mYTq-Ke2pAApFvgs',
      };
      expect(() => x25519.toRawPrivateKey(invalidJwk)).toThrow(
        'Invalid JWK: malformed Base64URL in d parameter',
      );
    });
  });

  describe('toRawPublicKey', () => {
    it('should convert a JWK to a raw public key', () => {
      const privateKey = x25519.randomPrivateKey();
      const publicKey = x25519.getPublicKey(privateKey);
      const jwk = x25519.toJwkPublicKey(publicKey);
      const rawPublicKey = x25519.toRawPublicKey(jwk);
      expect(rawPublicKey).toBeInstanceOf(Uint8Array);
      expect(rawPublicKey.length).toBe(32);
      expect(rawPublicKey).toEqual(publicKey);
    });
    it('should throw an error for invalid JWK', () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'X25519',
        x: 'invalid-base64url!',
      };
      expect(() => x25519.toRawPublicKey(invalidJwk)).toThrow(
        'Invalid JWK: malformed Base64URL in x parameter',
      );
    });
  });

  describe('isValidPrivateKey', () => {
    it('should return true for a valid private key', () => {
      const privateKey = x25519.randomPrivateKey();
      expect(x25519.isValidPrivateKey(privateKey)).toBe(true);
    });
    it('should return false for an invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      expect(x25519.isValidPrivateKey(invalidPrivateKey)).toBe(false);
    });
  });

  describe('isValidPublicKey', () => {
    it('should return true for a valid public key', () => {
      const privateKey = x25519.randomPrivateKey();
      const publicKey = x25519.getPublicKey(privateKey);
      expect(x25519.isValidPublicKey(publicKey)).toBe(true);
    });
    it('should return false for an invalid public key', () => {
      const invalidPublicKey = new Uint8Array(32); // All zeros
      expect(x25519.isValidPublicKey(invalidPublicKey)).toBe(false);
    });
  });

  describe('getSharedSecret', () => {
    it('should compute a shared secret', () => {
      const privateKeyA = x25519.randomPrivateKey();
      const privateKeyB = x25519.randomPrivateKey();
      const publicKeyB = x25519.getPublicKey(privateKeyB);
      const sharedSecretA = x25519.getSharedSecret({
        privateKey: privateKeyA,
        publicKey: publicKeyB,
      });
      expect(sharedSecretA).toBeInstanceOf(Uint8Array);
      expect(sharedSecretA.length).toBe(32);
    });
    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      const publicKey = x25519.getPublicKey(x25519.randomPrivateKey());
      expect(() =>
        x25519.getSharedSecret({ privateKey: invalidPrivateKey, publicKey }),
      ).toThrow('Invalid X25519 private key');
    });
    it('should throw an error for invalid public key', () => {
      const privateKey = x25519.randomPrivateKey();
      const invalidPublicKey = new Uint8Array(32); // All zeros
      expect(() =>
        x25519.getSharedSecret({ privateKey, publicKey: invalidPublicKey }),
      ).toThrow('Invalid X25519 public key');
    });
  });
});
