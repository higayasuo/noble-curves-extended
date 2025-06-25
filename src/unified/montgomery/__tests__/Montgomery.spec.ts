import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { Montgomery } from '../Montgomery';
import { randomBytes } from '@noble/hashes/utils';

describe('Montgomery', () => {
  const curve = createX25519(randomBytes);
  const montgomery = new Montgomery(curve, randomBytes);

  it('should have correct curve name', () => {
    expect(montgomery.curveName).toBe('X25519');
  });

  describe('getCurve', () => {
    it('should return the same curve instance passed to the constructor', () => {
      // Default type
      expect(montgomery.getCurve()).toBe(curve);
      // Explicit type
      const returned = montgomery.getCurve();
      expect(returned).toBe(curve);
    });
  });

  describe('randomPrivateKey', () => {
    it('should generate a valid private key', () => {
      const privateKey = montgomery.randomPrivateKey();
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(curve.GuBytes.length);
    });
  });

  describe('getPublicKey', () => {
    it('should generate a valid public key from a private key', () => {
      const privateKey = montgomery.randomPrivateKey();
      const publicKey = montgomery.getPublicKey(privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(curve.GuBytes.length);
    });
    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(curve.GuBytes.length - 1); // All zeros
      expect(() => montgomery.getPublicKey(invalidPrivateKey)).toThrow(
        'Failed to get public key',
      );
    });
  });

  describe('getSharedSecret', () => {
    it('should compute a shared secret', () => {
      const privateKeyA = montgomery.randomPrivateKey();
      const privateKeyB = montgomery.randomPrivateKey();
      const publicKeyB = montgomery.getPublicKey(privateKeyB);
      const sharedSecretA = montgomery.getSharedSecret({
        privateKey: privateKeyA,
        publicKey: publicKeyB,
      });
      expect(sharedSecretA).toBeInstanceOf(Uint8Array);
      expect(sharedSecretA.length).toBe(curve.GuBytes.length);
    });
    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(curve.GuBytes.length - 1); // invalid length
      const publicKey = montgomery.getPublicKey(montgomery.randomPrivateKey());
      expect(() =>
        montgomery.getSharedSecret({
          privateKey: invalidPrivateKey,
          publicKey,
        }),
      ).toThrow('Failed to compute shared secret');
    });
    it('should throw an error for invalid public key', () => {
      const privateKey = montgomery.randomPrivateKey();
      const invalidPublicKey = new Uint8Array(curve.GuBytes.length - 1); // invalid length
      expect(() =>
        montgomery.getSharedSecret({ privateKey, publicKey: invalidPublicKey }),
      ).toThrow('Failed to compute shared secret');
    });
  });

  describe('toJwkPrivateKey', () => {
    it('should convert a private key to JWK format', () => {
      const privateKey = montgomery.randomPrivateKey();
      const jwk = montgomery.toJwkPrivateKey(privateKey);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'X25519');
      expect(jwk).toHaveProperty('d');
      expect(jwk).toHaveProperty('x');
    });
    it('should throw an error for invalid private key', () => {
      const invalidPrivateKey = new Uint8Array(curve.GuBytes.length - 1); // invalid length
      expect(() => montgomery.toJwkPrivateKey(invalidPrivateKey)).toThrow(
        'Failed to convert private key to JWK',
      );
    });
  });

  describe('toJwkPublicKey', () => {
    it('should convert a public key to JWK format', () => {
      const privateKey = montgomery.randomPrivateKey();
      const publicKey = montgomery.getPublicKey(privateKey);
      const jwk = montgomery.toJwkPublicKey(publicKey);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'X25519');
      expect(jwk).toHaveProperty('x');
    });
    it('should throw an error for invalid public key', () => {
      const invalidPublicKey = new Uint8Array(curve.GuBytes.length - 1); // invalid length
      expect(() => montgomery.toJwkPublicKey(invalidPublicKey)).toThrow(
        'Failed to convert public key to JWK',
      );
    });
  });

  describe('toRawPrivateKey', () => {
    it('should convert a JWK to a raw private key', () => {
      const privateKey = montgomery.randomPrivateKey();
      const jwk = montgomery.toJwkPrivateKey(privateKey);
      const rawPrivateKey = montgomery.toRawPrivateKey(jwk);
      expect(rawPrivateKey).toBeInstanceOf(Uint8Array);
      expect(rawPrivateKey.length).toBe(curve.GuBytes.length);
      expect(rawPrivateKey).toEqual(privateKey);
    });
    it('should throw an error for invalid JWK', () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'X25519',
        d: 'invalid-base64url!',
        x: 'hSDwCYkwp1R0i33ctD73Wg2_Og0mYTq-Ke2pAApFvgs',
      };
      expect(() => montgomery.toRawPrivateKey(invalidJwk)).toThrow(
        'Failed to convert JWK to raw private key',
      );
    });
  });

  describe('toRawPublicKey', () => {
    it('should convert a JWK to a raw public key', () => {
      const privateKey = montgomery.randomPrivateKey();
      const publicKey = montgomery.getPublicKey(privateKey);
      const jwk = montgomery.toJwkPublicKey(publicKey);
      const rawPublicKey = montgomery.toRawPublicKey(jwk);
      expect(rawPublicKey).toBeInstanceOf(Uint8Array);
      expect(rawPublicKey.length).toBe(curve.GuBytes.length);
      expect(rawPublicKey).toEqual(publicKey);
    });
    it('should throw an error for invalid JWK', () => {
      const invalidJwk = {
        kty: 'OKP',
        crv: 'X25519',
        x: 'invalid-base64url!',
      };
      expect(() => montgomery.toRawPublicKey(invalidJwk)).toThrow(
        'Failed to convert JWK to raw public key',
      );
    });
  });
});
