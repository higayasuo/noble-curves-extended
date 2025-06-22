import { describe, it, expect } from 'vitest';
import {
  ed25519ToRawPrivateKey,
  ed25519ToRawPrivateKeyInternal,
} from '../ed25519ToRawPrivateKey';
import { ed25519ToJwkPrivateKey } from '../ed25519ToJwkPrivateKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('ed25519ToRawPrivateKey', () => {
  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = ed25519ToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });

  describe('error handling', () => {
    describe('d parameter', () => {
      it('should throw an error for missing d parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
        const { d, ...invalidJwk } = jwk;
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for null d parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: null };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for undefined d parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: undefined };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for empty string d parameter (results in length 0)', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: '' };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for non-string d parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: 123 };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for malformed Base64URL in d parameter', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: 'invalid-base64url!' };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for invalid private key length (not 32 bytes)', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);

        // Create a 16-byte private key (invalid length)
        const invalidPrivateKey = new Uint8Array(16);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for invalid private key length (64 bytes)', () => {
        const curve = createEd25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey);

        // Create a 64-byte private key (invalid length for Ed25519)
        const invalidPrivateKey = new Uint8Array(64);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        };
        expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for d that does not match public key', () => {
        const curve = createEd25519(randomBytes);
        const privateKey1 = curve.utils.randomPrivateKey();
        const privateKey2 = curve.utils.randomPrivateKey();

        // Create JWK with private key 1 but public key from private key 2
        const jwk = ed25519ToJwkPrivateKey(curve, privateKey1);
        const jwk2 = ed25519ToJwkPrivateKey(curve, privateKey2);
        const jwkWithMismatchedD = {
          ...jwk,
          x: jwk2.x, // Use x from different key
        };

        expect(() =>
          ed25519ToRawPrivateKey(curve, jwkWithMismatchedD as any),
        ).toThrow('Failed to convert JWK to raw private key');
      });
    });

    describe('inherited public key validation', () => {
      describe('kty parameter', () => {
        it('should throw an error for missing kty parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const { kty, ...invalidJwk } = jwk;
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null kty parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: null };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for undefined kty parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: undefined };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for invalid kty', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: 'EC' };
          expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('crv parameter', () => {
        it('should throw an error for missing crv parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const { crv, ...invalidJwk } = jwk;
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null crv parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: null };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for undefined crv parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: undefined };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for invalid crv', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: 'X25519' };
          expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('x parameter', () => {
        it('should throw an error for missing x parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const { x, ...invalidJwk } = jwk;
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null x parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: null };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for undefined x parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: undefined };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for empty string x parameter (results in length 0)', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: '' };
          expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for non-string x parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: 123 };
          expect(() =>
            ed25519ToRawPrivateKey(curve, invalidJwk as any),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for malformed Base64URL in x parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: 'invalid-base64url!' };
          expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('alg parameter', () => {
        it('should throw an error for empty string alg parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, alg: '' };
          expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for invalid alg parameter', () => {
          const curve = createEd25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, alg: 'ES256' };
          expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });
    });
  });

  describe('internal function', () => {
    it('should work with internal function', () => {
      const curve = createEd25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = ed25519ToRawPrivateKeyInternal(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });
});
