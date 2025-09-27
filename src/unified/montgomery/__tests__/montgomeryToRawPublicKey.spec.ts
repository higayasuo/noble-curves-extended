import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import {
  montgomeryToRawPublicKey,
  montgomeryToRawPublicKeyInternal,
} from '../montgomeryToRawPublicKey';
import { montgomeryToJwkPublicKey } from '../montgomeryToJwkPublicKey';
import type { JwkPublicKey } from '../../types';

describe('montgomeryToRawPublicKey', () => {
  const curve = createX25519(randomBytes);

  describe('montgomeryToRawPublicKey', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
      const rawPublicKey = montgomeryToRawPublicKey(curve, 32, 'X25519', jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });

    it('should throw generic error for invalid JWK', () => {
      const invalidJwk = { kty: 'EC' } as JwkPublicKey;
      expect(() =>
        montgomeryToRawPublicKey(curve, 32, 'X25519', invalidJwk),
      ).toThrow('Failed to convert JWK to raw public key');
    });
  });

  describe('montgomeryToRawPublicKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it('should convert a valid JWK to a raw public key', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const rawPublicKey = montgomeryToRawPublicKeyInternal(
          curve,
          32,
          'X25519',
          jwk,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });
    });

    describe('kty parameter validation', () => {
      it('should throw error for missing kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const { kty, ...jwkWithoutKty } = jwk;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithoutKty as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for null kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithNullKty = { ...jwk, kty: null } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, 32, 'X25519', jwkWithNullKty),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for wrong kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithWrongKty = { ...jwk, kty: 'EC' } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithWrongKty,
          ),
        ).toThrow('Invalid key type: EC, expected OKP');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for missing crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const { crv, ...jwkWithoutCrv } = jwk;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithoutCrv as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for null crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithNullCrv = { ...jwk, crv: null } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, 32, 'X25519', jwkWithNullCrv),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for wrong crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'Ed25519' } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithWrongCrv,
          ),
        ).toThrow('Invalid curve: Ed25519, expected X25519');
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const { x, ...jwkWithoutX } = jwk;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithoutX as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for null x', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithNullX = { ...jwk, x: null } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, 32, 'X25519', jwkWithNullX),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for invalid x type', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithInvalidXType = {
          ...jwk,
          x: 123,
        } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithInvalidXType,
          ),
        ).toThrow('Invalid parameter type for x');
      });

      it('should throw error for invalid x encoding', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, 32, 'X25519', publicKey);
        const jwkWithInvalidX = {
          ...jwk,
          x: 'invalid-base64url!',
        } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            32,
            'X25519',
            jwkWithInvalidX,
          ),
        ).toThrow('Malformed encoding for x');
      });

      it('should throw error for wrong x length', () => {
        const invalidPublicKey = new Uint8Array(31);
        const jwk = montgomeryToJwkPublicKey(
          curve,
          32,
          'X25519',
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const jwkWithWrongX = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, 32, 'X25519', jwkWithWrongX),
        ).toThrow('Invalid the length of the key data for x: 31, expected 32');
      });
    });
  });
});
