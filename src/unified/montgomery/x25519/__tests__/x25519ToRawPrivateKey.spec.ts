import { describe, it, expect } from 'vitest';
import { createX25519 } from '@/curves/montgomery/x25519';
import { randomBytes } from '@noble/hashes/utils';
import {
  x25519ToRawPrivateKey,
  x25519ToRawPrivateKeyInternal,
} from '../x25519ToRawPrivateKey';
import { x25519ToJwkPrivateKey } from '../x25519ToJwkPrivateKey';
import type { JwkPrivateKey } from '../../../types';

describe('x25519ToRawPrivateKey', () => {
  describe('valid JWK conversion', () => {
    it('should convert a valid JWK to a raw private key', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = x25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = x25519ToRawPrivateKey(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });

  describe('error handling', () => {
    describe('d parameter', () => {
      it('should throw an error for missing d parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const { d, ...invalidJwk } = jwk;
        expect(() =>
          x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
        ).toThrow('Failed to convert JWK to raw private key');
      });

      it('should throw an error for null d parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: null } as unknown as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for undefined d parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: undefined } as unknown as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for empty string d parameter (results in length 0)', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: '' } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for non-string d parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: 123 } as unknown as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for malformed Base64URL in d parameter', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidJwk = { ...jwk, d: 'invalid-base64url!' } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with length 16', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(16);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with length 31', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(31);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with length 33', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(33);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with length 48', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(48);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with length 64', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(64);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for private key with length 128', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);
        const invalidPrivateKey = new Uint8Array(128);
        const invalidJwk = {
          ...jwk,
          d: Buffer.from(invalidPrivateKey).toString('base64url'),
        } as JwkPrivateKey;
        expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });

      it('should throw an error for d that does not match public key', () => {
        const curve = createX25519(randomBytes);
        const privateKey1 = curve.utils.randomPrivateKey();
        const privateKey2 = curve.utils.randomPrivateKey();

        // Create JWK with private key 1 but public key from private key 2
        const jwk = x25519ToJwkPrivateKey(curve, privateKey1);
        const jwk2 = x25519ToJwkPrivateKey(curve, privateKey2);
        const jwkWithMismatchedD = {
          ...jwk,
          x: jwk2.x, // Use x from different key
        };

        expect(() =>
          x25519ToRawPrivateKey(curve, jwkWithMismatchedD as JwkPrivateKey),
        ).toThrow('Failed to convert JWK to raw private key');
      });

      it('should throw an error for d that generates different public key', () => {
        const curve = createX25519(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const jwk = x25519ToJwkPrivateKey(curve, privateKey);

        // Create a different valid private key that will generate a different public key
        const differentPrivateKey = curve.utils.randomPrivateKey();
        const differentJwk = x25519ToJwkPrivateKey(curve, differentPrivateKey);

        // Use the d from different key but keep the original x
        const jwkWithWrongD = {
          ...jwk,
          d: differentJwk.d, // Use d from different key
        };

        expect(() => x25519ToRawPrivateKey(curve, jwkWithWrongD)).toThrow(
          'Failed to convert JWK to raw private key',
        );
      });
    });

    describe('inherited public key validation', () => {
      describe('kty parameter', () => {
        it('should throw an error for missing kty parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const { kty, ...invalidJwk } = jwk;
          expect(() =>
            x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null kty parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: null } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for undefined kty parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            kty: undefined,
          } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for invalid kty', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, kty: 'EC' } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('crv parameter', () => {
        it('should throw an error for missing crv parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const { crv, ...invalidJwk } = jwk;
          expect(() =>
            x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null crv parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: null } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for undefined crv parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            crv: undefined,
          } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for invalid crv', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });

      describe('x parameter', () => {
        it('should throw an error for missing x parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const { x, ...invalidJwk } = jwk;
          expect(() =>
            x25519ToRawPrivateKey(curve, invalidJwk as JwkPrivateKey),
          ).toThrow('Failed to convert JWK to raw private key');
        });

        it('should throw an error for null x parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: null } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for undefined x parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            x: undefined,
          } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for empty string x parameter (results in length 0)', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: '' } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for non-string x parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for malformed Base64URL in x parameter', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidJwk = {
            ...jwk,
            x: 'invalid-base64url!',
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with length 16', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(16);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with length 31', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(31);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with length 33', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(33);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with length 48', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(48);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with length 64', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(64);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });

        it('should throw an error for public key with length 128', () => {
          const curve = createX25519(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwk = x25519ToJwkPrivateKey(curve, privateKey);
          const invalidPublicKey = new Uint8Array(128);
          const invalidJwk = {
            ...jwk,
            x: Buffer.from(invalidPublicKey).toString('base64url'),
          } as JwkPrivateKey;
          expect(() => x25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
            'Failed to convert JWK to raw private key',
          );
        });
      });
    });
  });

  describe('internal function', () => {
    it('should work with internal function', () => {
      const curve = createX25519(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = x25519ToJwkPrivateKey(curve, privateKey);
      const rawPrivateKey = x25519ToRawPrivateKeyInternal(curve, jwk);
      expect(rawPrivateKey).toEqual(privateKey);
    });
  });
});
