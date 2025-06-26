import { describe, it, expect } from 'vitest';
import {
  edwardsToRawPublicKey,
  edwardsToRawPublicKeyInternal,
} from '../edwardsToRawPublicKey';
import { edwardsToJwkPublicKey } from '../edwardsToJwkPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('edwardsToRawPublicKey', () => {
  describe('edwardsToRawPublicKey', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = edwardsToJwkPublicKey(curve, publicKey);
      const rawPublicKey = edwardsToRawPublicKey(curve, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createEd25519(randomBytes);
      const invalidJwk = { kty: 'EC' } as any;
      expect(() => edwardsToRawPublicKey(curve, invalidJwk)).toThrow(
        'Failed to convert JWK to raw public key',
      );
    });
  });

  describe('edwardsToRawPublicKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it('should convert a valid JWK to a raw public key', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const rawPublicKey = edwardsToRawPublicKeyInternal(curve, jwk);
        expect(rawPublicKey).toEqual(publicKey);
      });

      it('should accept JWK without alg parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { alg, ...jwkWithoutAlg } = jwk;
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          jwkWithoutAlg as any,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });
    });

    describe('kty parameter validation', () => {
      it('should throw error for missing kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { kty, ...jwkWithoutKty } = jwk;
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithoutKty as any),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for null kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithNullKty = { ...jwk, kty: null as any };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithNullKty),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for wrong kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithWrongKty = { ...jwk, kty: 'EC' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithWrongKty),
        ).toThrow('Invalid key type: EC, expected OKP');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for missing crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { crv, ...jwkWithoutCrv } = jwk;
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithoutCrv as any),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for null crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithNullCrv = { ...jwk, crv: null as any };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithNullCrv),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for wrong crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'X25519' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithWrongCrv),
        ).toThrow('Invalid curve: X25519, expected Ed25519');
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const { x, ...jwkWithoutX } = jwk;
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithoutX as any),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for null x', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithNullX = { ...jwk, x: null as any };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithNullX),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for invalid x type', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithInvalidXType = { ...jwk, x: 123 as any };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithInvalidXType),
        ).toThrow('Invalid parameter type for x');
      });

      it('should throw error for invalid x encoding', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithInvalidX = { ...jwk, x: 'invalid-base64url!' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithInvalidX),
        ).toThrow('Malformed encoding for x');
      });

      it('should throw error for wrong x length', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const invalidPublicKey = new Uint8Array(16);
        const jwkWithWrongX = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithWrongX),
        ).toThrow(
          `Invalid the length of the key data for x: 16, expected ${curve.CURVE.nByteLength}`,
        );
      });
    });

    describe('alg parameter validation', () => {
      it('should throw error for wrong alg', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithWrongAlg = { ...jwk, alg: 'ES256' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, jwkWithWrongAlg),
        ).toThrow('Invalid algorithm: ES256, expected EdDSA');
      });

      it('should accept null alg', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithNullAlg = { ...jwk, alg: null as any };
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          jwkWithNullAlg,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });

      it('should accept undefined alg', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, publicKey);
        const jwkWithUndefinedAlg = { ...jwk, alg: undefined as any };
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          jwkWithUndefinedAlg,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });
    });
  });
});
