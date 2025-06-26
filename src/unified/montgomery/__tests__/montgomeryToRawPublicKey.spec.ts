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
      const jwk = montgomeryToJwkPublicKey(curve, publicKey);
      const rawPublicKey = montgomeryToRawPublicKey(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });

    it('should throw generic error for invalid JWK', () => {
      const invalidJwk = { kty: 'EC' } as JwkPublicKey;
      expect(() => montgomeryToRawPublicKey(curve, invalidJwk)).toThrow(
        'Failed to convert JWK to raw public key',
      );
    });
  });

  describe('montgomeryToRawPublicKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it('should convert a valid JWK to a raw public key', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const rawPublicKey = montgomeryToRawPublicKeyInternal(curve, jwk);
        expect(rawPublicKey).toEqual(publicKey);
      });
    });

    describe('kty parameter validation', () => {
      it('should throw error for missing kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const { kty, ...jwkWithoutKty } = jwk;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            jwkWithoutKty as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for null kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithNullKty = { ...jwk, kty: null } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithNullKty),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for wrong kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithWrongKty = { ...jwk, kty: 'EC' } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithWrongKty),
        ).toThrow('Invalid key type: EC, expected OKP');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for missing crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const { crv, ...jwkWithoutCrv } = jwk;
        expect(() =>
          montgomeryToRawPublicKeyInternal(
            curve,
            jwkWithoutCrv as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for null crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithNullCrv = { ...jwk, crv: null } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithNullCrv),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for wrong crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'Ed25519' } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithWrongCrv),
        ).toThrow('Invalid curve: Ed25519, expected X25519');
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const { x, ...jwkWithoutX } = jwk;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithoutX as JwkPublicKey),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for null x', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithNullX = { ...jwk, x: null } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithNullX),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for invalid x type', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithInvalidXType = {
          ...jwk,
          x: 123,
        } as unknown as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithInvalidXType),
        ).toThrow('Invalid parameter type for x');
      });

      it('should throw error for invalid x encoding', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = montgomeryToJwkPublicKey(curve, publicKey);
        const jwkWithInvalidX = {
          ...jwk,
          x: 'invalid-base64url!',
        } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithInvalidX),
        ).toThrow('Malformed encoding for x');
      });

      it('should throw error for wrong x length', () => {
        const invalidPublicKey = new Uint8Array(curve.GuBytes.length - 1);
        const jwk = montgomeryToJwkPublicKey(
          curve,
          curve.getPublicKey(curve.utils.randomPrivateKey()),
        );
        const jwkWithWrongX = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        } as JwkPublicKey;
        expect(() =>
          montgomeryToRawPublicKeyInternal(curve, jwkWithWrongX),
        ).toThrow(
          `Invalid the length of the key data for x: ${
            curve.GuBytes.length - 1
          }, expected ${curve.GuBytes.length}`,
        );
      });
    });
  });
});
