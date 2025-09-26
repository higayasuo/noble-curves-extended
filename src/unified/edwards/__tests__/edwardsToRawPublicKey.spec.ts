import { describe, it, expect } from 'vitest';
import {
  edwardsToRawPublicKey,
  edwardsToRawPublicKeyInternal,
} from '../edwardsToRawPublicKey';
import { edwardsToJwkPublicKey } from '../edwardsToJwkPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { JwkPublicKey } from '@/unified/types';

const keyByteLength = 32;

describe('edwardsToRawPublicKey', () => {
  describe('edwardsToRawPublicKey', () => {
    it('should convert a valid JWK to a raw public key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
      const rawPublicKey = edwardsToRawPublicKey(curve, keyByteLength, jwk);
      expect(rawPublicKey).toEqual(publicKey);
    });

    it('should throw generic error for invalid JWK', () => {
      const curve = createEd25519(randomBytes);
      const invalidJwk = { kty: 'EC' } as JwkPublicKey;
      expect(() =>
        edwardsToRawPublicKey(curve, keyByteLength, invalidJwk),
      ).toThrow('Failed to convert JWK to raw public key');
    });
  });

  describe('edwardsToRawPublicKeyInternal', () => {
    describe('valid JWK conversion', () => {
      it('should convert a valid JWK to a raw public key', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          keyByteLength,
          jwk,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });

      it('should accept JWK without alg parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const { alg, ...jwkWithoutAlg } = jwk;
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          keyByteLength,
          jwkWithoutAlg as unknown as JwkPublicKey,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });
    });

    describe('kty parameter validation', () => {
      it('should throw error for missing kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const { kty, ...jwkWithoutKty } = jwk;
        expect(() =>
          edwardsToRawPublicKeyInternal(
            curve,
            keyByteLength,
            jwkWithoutKty as unknown as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for null kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithNullKty = { ...jwk, kty: null as unknown as string };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithNullKty),
        ).toThrow('Missing required parameter for kty');
      });

      it('should throw error for wrong kty', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithWrongKty = { ...jwk, kty: 'EC' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithWrongKty),
        ).toThrow('Invalid key type: EC, expected OKP');
      });
    });

    describe('crv parameter validation', () => {
      it('should throw error for missing crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const { crv, ...jwkWithoutCrv } = jwk;
        expect(() =>
          edwardsToRawPublicKeyInternal(
            curve,
            keyByteLength,
            jwkWithoutCrv as unknown as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for null crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithNullCrv = { ...jwk, crv: null as any };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithNullCrv),
        ).toThrow('Missing required parameter for crv');
      });

      it('should throw error for wrong crv', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithWrongCrv = { ...jwk, crv: 'X25519' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithWrongCrv),
        ).toThrow('Invalid curve: X25519, expected Ed25519');
      });
    });

    describe('x parameter validation', () => {
      it('should throw error for missing x', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const { x, ...jwkWithoutX } = jwk;
        expect(() =>
          edwardsToRawPublicKeyInternal(
            curve,
            keyByteLength,
            jwkWithoutX as unknown as JwkPublicKey,
          ),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for null x', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithNullX = { ...jwk, x: null as unknown as string };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithNullX),
        ).toThrow('Missing required parameter for x');
      });

      it('should throw error for invalid x type', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithInvalidXType = { ...jwk, x: 123 as unknown as string };
        expect(() =>
          edwardsToRawPublicKeyInternal(
            curve,
            keyByteLength,
            jwkWithInvalidXType,
          ),
        ).toThrow('Invalid parameter type for x');
      });

      it('should throw error for invalid x encoding', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithInvalidX = { ...jwk, x: 'invalid-base64url!' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithInvalidX),
        ).toThrow('Malformed encoding for x');
      });

      it('should throw error for wrong x length', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const invalidPublicKey = new Uint8Array(16);
        const jwkWithWrongX = {
          ...jwk,
          x: Buffer.from(invalidPublicKey).toString('base64url'),
        };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithWrongX),
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
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithWrongAlg = { ...jwk, alg: 'ES256' };
        expect(() =>
          edwardsToRawPublicKeyInternal(curve, keyByteLength, jwkWithWrongAlg),
        ).toThrow('Invalid algorithm: ES256, expected EdDSA');
      });

      it('should accept null alg', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithNullAlg = { ...jwk, alg: null as unknown as string };
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          keyByteLength,
          jwkWithNullAlg,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });

      it('should accept undefined alg', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const jwk = edwardsToJwkPublicKey(curve, keyByteLength, publicKey);
        const jwkWithUndefinedAlg = {
          ...jwk,
          alg: undefined as unknown as string,
        };
        const rawPublicKey = edwardsToRawPublicKeyInternal(
          curve,
          keyByteLength,
          jwkWithUndefinedAlg,
        );
        expect(rawPublicKey).toEqual(publicKey);
      });
    });
  });
});
