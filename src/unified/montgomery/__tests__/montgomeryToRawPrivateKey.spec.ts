import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import {
  montgomeryToRawPrivateKey,
  montgomeryToRawPrivateKeyInternal,
} from '../montgomeryToRawPrivateKey';
import { montgomeryToJwkPrivateKey } from '../montgomeryToJwkPrivateKey';
import type { JwkPrivateKey } from '../../types';

describe('montgomeryToRawPrivateKey', () => {
  const curve = createX25519(randomBytes);

  describe('montgomeryToRawPrivateKey', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
      const rawPrivateKey = montgomeryToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });

    it('should throw generic error for invalid JWK', () => {
      const invalidJwk = { kty: 'EC' } as JwkPrivateKey;
      expect(() => montgomeryToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Failed to convert JWK to raw private key',
      );
    });
  });

  describe('montgomeryToRawPrivateKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it('should convert a valid JWK to a raw private key', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const rawPrivateKey = montgomeryToRawPrivateKeyInternal(curve, jwk);
        expect(rawPrivateKey).toEqual(privateKey);
      });
    });

    describe('d parameter validation', () => {
      it('should throw error for missing d', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const { d, ...jwkWithoutD } = jwk;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(
            curve,
            jwkWithoutD as JwkPrivateKey,
          ),
        ).toThrow('Missing required parameter for d');
      });

      it('should throw error for null d', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const jwkWithNullD = { ...jwk, d: null } as unknown as JwkPrivateKey;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(curve, jwkWithNullD),
        ).toThrow('Missing required parameter for d');
      });

      it('should throw error for invalid d type', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const jwkWithInvalidDType = {
          ...jwk,
          d: 123,
        } as unknown as JwkPrivateKey;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(curve, jwkWithInvalidDType),
        ).toThrow('Invalid parameter type for d');
      });

      it('should throw error for invalid d encoding', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const jwkWithInvalidD = {
          ...jwk,
          d: 'invalid-base64url!',
        } as JwkPrivateKey;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(curve, jwkWithInvalidD),
        ).toThrow('Malformed encoding for d');
      });

      it('should throw error for wrong d length', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const invalidPrivateKey = new Uint8Array(31);
        const jwkWithWrongD = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(curve, jwkWithWrongD),
        ).toThrow(
          'Invalid the length of the key data for d: 31, expected 32',
        );
      });

      it('should throw error for d that does not match public key', () => {
        const privateKey1 = curve.utils.randomPrivateKey();
        const privateKey2 = curve.utils.randomPrivateKey();

        // Create JWK with private key 1 but public key from private key 2
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey1);
        const jwk2 = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey2);
        const jwkWithMismatchedD = {
          ...jwk,
          x: jwk2.x, // Use x from different key
        };

        expect(() =>
          montgomeryToRawPrivateKeyInternal(
            curve,
            jwkWithMismatchedD as JwkPrivateKey,
          ),
        ).toThrow(
          'The public key derived from the private key does not match the public key in the JWK',
        );
      });
    });

    describe('kty parameter validation', () => {
      it('should throw error for wrong kty', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const jwkWithWrongKty = { ...jwk, kty: 'EC' } as JwkPrivateKey;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(curve, jwkWithWrongKty),
        ).toThrow('Invalid key type: EC, expected OKP');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for wrong crv', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'Ed25519' } as JwkPrivateKey;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(curve, jwkWithWrongCrv),
        ).toThrow('Invalid curve: Ed25519, expected X25519');
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = montgomeryToJwkPrivateKey(curve, 32, 'X25519', privateKey);
        const { x, ...jwkWithoutX } = jwk;
        expect(() =>
          montgomeryToRawPrivateKeyInternal(
            curve,
            jwkWithoutX as JwkPrivateKey,
          ),
        ).toThrow('Missing required parameter for x');
      });
    });
  });
});
