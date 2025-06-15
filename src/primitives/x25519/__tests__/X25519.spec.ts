import { describe, it, expect } from 'vitest';
import { x25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { X25519 } from '../X25519';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('X25519', () => {
  const curve = x25519(randomBytes);
  const x25519Instance = new X25519(curve, randomBytes);

  it('should have correct curve and algorithm identifiers', () => {
    expect(x25519Instance.crv).toBe('X25519');
    expect(x25519Instance.alg).toBe('ECDH-ES');
  });

  describe('randomPrivateKey', () => {
    it('should generate a valid private key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);
      expect(x25519Instance.isValidPrivateKey(privateKey)).toBe(true);
    });
  });

  describe('getPublicKey', () => {
    it('should generate a valid public key from a private key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const publicKey = x25519Instance.getPublicKey(privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);
      expect(x25519Instance.isValidPublicKey(publicKey)).toBe(true);
    });

    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      expect(() => x25519Instance.getPublicKey(invalidPrivateKey)).toThrow(
        'Invalid X25519 private key',
      );
    });
  });

  describe('toJwkPrivateKey', () => {
    it('should convert a private key to JWK format', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const jwk = x25519Instance.toJwkPrivateKey(privateKey);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'X25519');
      expect(jwk).toHaveProperty('d');
      expect(jwk).toHaveProperty('x');
    });

    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      expect(() => x25519Instance.toJwkPrivateKey(invalidPrivateKey)).toThrow(
        'Invalid X25519 private key',
      );
    });
  });

  describe('toJwkPublicKey', () => {
    it('should convert a public key to JWK format', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const publicKey = x25519Instance.getPublicKey(privateKey);
      const jwk = x25519Instance.toJwkPublicKey(publicKey);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'X25519');
      expect(jwk).toHaveProperty('x');
    });

    it('should throw an error for invalid public key', () => {
      const invalidPublicKey = new Uint8Array(32); // All zeros
      expect(() => x25519Instance.toJwkPublicKey(invalidPublicKey)).toThrow(
        'Invalid X25519 public key',
      );
    });
  });

  describe('toRawPrivateKey', () => {
    it('should convert a JWK to a raw private key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const jwk = x25519Instance.toJwkPrivateKey(privateKey);
      const rawPrivateKey = x25519Instance.toRawPrivateKey(jwk);
      expect(rawPrivateKey).toBeInstanceOf(Uint8Array);
      expect(rawPrivateKey.length).toBe(32);
      expect(rawPrivateKey).toEqual(privateKey);
    });

    it('should throw an error for invalid JWK', () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'X25519',
        d: 'invalid-base64url!',
        x: 'hSDwCYkwp1R0i33ctD73Wg2_Og0mYTq-Ke2pAApFvgs', // RFC 7748 test vector
      };
      expect(() => x25519Instance.toRawPrivateKey(invalidJwk)).toThrow(
        'Invalid JWK: malformed Base64URL in d parameter',
      );
    });
  });

  describe('toRawPublicKey', () => {
    it('should convert a JWK to a raw public key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const publicKey = x25519Instance.getPublicKey(privateKey);
      const jwk = x25519Instance.toJwkPublicKey(publicKey);
      const rawPublicKey = x25519Instance.toRawPublicKey(jwk);
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
      expect(() => x25519Instance.toRawPublicKey(invalidJwk)).toThrow(
        'Invalid JWK: malformed Base64URL in x parameter',
      );
    });
  });

  describe('isValidPrivateKey', () => {
    it('should return true for a valid private key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      expect(x25519Instance.isValidPrivateKey(privateKey)).toBe(true);
    });

    it('should return false for an invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      expect(x25519Instance.isValidPrivateKey(invalidPrivateKey)).toBe(false);
    });
  });

  describe('isValidPublicKey', () => {
    it('should return true for a valid public key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const publicKey = x25519Instance.getPublicKey(privateKey);
      expect(x25519Instance.isValidPublicKey(publicKey)).toBe(true);
    });

    it('should return false for an invalid public key', () => {
      const invalidPublicKey = new Uint8Array(32); // All zeros
      expect(x25519Instance.isValidPublicKey(invalidPublicKey)).toBe(false);
    });
  });

  describe('getSharedSecret', () => {
    it('should compute the same shared secret for both parties', () => {
      const alicePrivateKey = x25519Instance.randomPrivateKey();
      const alicePublicKey = x25519Instance.getPublicKey(alicePrivateKey);
      const bobPrivateKey = x25519Instance.randomPrivateKey();
      const bobPublicKey = x25519Instance.getPublicKey(bobPrivateKey);

      const aliceSharedSecret = x25519Instance.getSharedSecret({
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey,
      });
      const bobSharedSecret = x25519Instance.getSharedSecret({
        privateKey: bobPrivateKey,
        publicKey: alicePublicKey,
      });

      expect(aliceSharedSecret).toEqual(bobSharedSecret);
    });

    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(32); // All zeros
      const publicKey = x25519Instance.getPublicKey(
        x25519Instance.randomPrivateKey(),
      );

      expect(() =>
        x25519Instance.getSharedSecret({
          privateKey: invalidPrivateKey,
          publicKey,
        }),
      ).toThrow('Invalid X25519 private key');
    });

    it('should throw an error for invalid public key', () => {
      const privateKey = x25519Instance.randomPrivateKey();
      const invalidPublicKey = new Uint8Array(32); // All zeros

      expect(() =>
        x25519Instance.getSharedSecret({
          privateKey,
          publicKey: invalidPublicKey,
        }),
      ).toThrow('Invalid X25519 public key');
    });
  });
});
