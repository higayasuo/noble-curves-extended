import { describe, it, expect } from 'vitest';
import {
  edwardsToRawPrivateKey,
  edwardsToRawPrivateKeyInternal,
} from '../edwardsToRawPrivateKey';
import { edwardsToJwkPrivateKey } from '../edwardsToJwkPrivateKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('edwardsToRawPrivateKey', () => {
  describe('edwardsToRawPrivateKey', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = edwardsToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = edwardsToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createEd25519(randomBytes);
      const invalidJwk = { kty: 'EC' } as any;
      expect(() => edwardsToRawPrivateKey(curve, invalidJwk)).toThrow(
        'Failed to convert JWK to raw private key',
      );
    });
  });

  describe('edwardsToRawPrivateKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it('should convert a valid JWK to a raw private key', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const rawPrivateKey = edwardsToRawPrivateKeyInternal(curve, jwk);
        expect(rawPrivateKey).toEqual(privateKey);
      });
    });

    describe('d parameter validation', () => {
      it('should throw error for missing d', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const { d, ...jwkWithoutD } = jwk;
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithoutD as any),
        ).toThrow('Missing required parameter for d');
      });

      it('should throw error for null d', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const jwkWithNullD = { ...jwk, d: null as any };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithNullD),
        ).toThrow('Missing required parameter for d');
      });

      it('should throw error for invalid d type', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const jwkWithInvalidDType = { ...jwk, d: 123 as any };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithInvalidDType),
        ).toThrow('Invalid parameter type for d');
      });

      it('should throw error for invalid d encoding', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const jwkWithInvalidD = { ...jwk, d: 'invalid-base64url!' };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithInvalidD),
        ).toThrow('Malformed encoding for d');
      });

      it('should throw error for wrong d length', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(16);
        const jwkWithWrongD = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithWrongD),
        ).toThrow(
          `Invalid the length of the key data for d: 16, expected ${curve.CURVE.nByteLength}`,
        );
      });

      it('should throw error for d that does not match public key', () => {
        const curve = createEd25519(randomBytes);
        const privateKey1 = curve.utils.randomPrivateKey();
        const privateKey2 = curve.utils.randomPrivateKey();

        // Create JWK with private key 1 but public key from private key 2
        const jwk = edwardsToJwkPrivateKey(curve, privateKey1);
        const jwk2 = edwardsToJwkPrivateKey(curve, privateKey2);
        const jwkWithMismatchedD = {
          ...jwk,
          x: jwk2.x, // Use x from different key
        };

        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithMismatchedD as any),
        ).toThrow(
          'The public key derived from the private key does not match the public key in the JWK',
        );
      });
    });

    describe('kty parameter validation', () => {
      it('should throw error for wrong kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const jwkWithWrongKty = { ...jwk, kty: 'EC' };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithWrongKty),
        ).toThrow('Invalid key type: EC, expected OKP');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for wrong crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'X25519' };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithWrongCrv),
        ).toThrow('Invalid curve: X25519, expected Ed25519');
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const { x, ...jwkWithoutX } = jwk;
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithoutX as any),
        ).toThrow('Missing required parameter for x');
      });
    });

    describe('alg parameter validation', () => {
      it('should throw error for wrong alg', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = edwardsToJwkPrivateKey(curve, privateKey);
        const jwkWithWrongAlg = { ...jwk, alg: 'ES256' };
        expect(() =>
          edwardsToRawPrivateKeyInternal(curve, jwkWithWrongAlg),
        ).toThrow('Invalid algorithm: ES256, expected EdDSA');
      });
    });
  });
});
