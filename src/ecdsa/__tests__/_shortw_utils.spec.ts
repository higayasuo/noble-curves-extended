import { describe, it, expect } from 'vitest';
import { createCurve, modifyCurve, createHmacFn } from '../_shortw_utils';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { RandomBytes } from '../../types';
import { secp256k1 as nobleSecp256k1 } from '@noble/curves/secp256k1';
import { WeierstrassOpts } from '../../abstract/_weierstrass';
import { Field } from '@noble/curves/abstract/modular';
import { CurveType } from '@noble/curves/abstract/weierstrass';

describe('_shortw_utils', () => {
  const randomBytes: RandomBytes = (bytesLength?: number) => {
    return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
  };

  describe('createHmacFn', () => {
    it('should create a valid HMAC function', () => {
      const hmacFn = createHmacFn(sha256);
      const key = new Uint8Array([1, 2, 3]);
      const msg1 = new Uint8Array([4, 5, 6]);
      const msg2 = new Uint8Array([7, 8, 9]);

      const result = hmacFn(key, msg1, msg2);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // SHA-256 output length
    });
  });

  describe('createCurve', () => {
    it('should create a curve with the specified hash function', () => {
      const Fp = Field(nobleSecp256k1.CURVE.p);
      const curveDef: Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'> = {
        Fp,
        n: nobleSecp256k1.CURVE.n,
        h: nobleSecp256k1.CURVE.h,
        a: nobleSecp256k1.CURVE.a,
        b: nobleSecp256k1.CURVE.b,
        Gx: nobleSecp256k1.CURVE.Gx,
        Gy: nobleSecp256k1.CURVE.Gy,
        lowS: true,
      };

      const curve = createCurve(curveDef, sha256, randomBytes);

      expect(curve).toHaveProperty('sign');
      expect(curve).toHaveProperty('verify');
      expect(curve).toHaveProperty('create');
    });
  });

  describe('modifyCurve', () => {
    it('should handle different input types for sign and verify', () => {
      const Fp = Field(nobleSecp256k1.CURVE.p);
      const curveDef: Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'> = {
        Fp,
        n: nobleSecp256k1.CURVE.n,
        h: nobleSecp256k1.CURVE.h,
        a: nobleSecp256k1.CURVE.a,
        b: nobleSecp256k1.CURVE.b,
        Gx: nobleSecp256k1.CURVE.Gx,
        Gy: nobleSecp256k1.CURVE.Gy,
        lowS: true,
      };

      const curve = createCurve(curveDef, sha256, randomBytes);
      const modifiedCurve = modifyCurve(curve);

      // Test with Uint8Array input
      const privateKey = new Uint8Array(curve.utils.randomPrivateKey());
      const message = new TextEncoder().encode('Hello, world!');
      const signature = modifiedCurve.sign(message, privateKey);
      const publicKey = modifiedCurve.getPublicKey(privateKey);

      // Verify with Uint8Array inputs
      const isValid = modifiedCurve.verify(signature, message, publicKey);
      expect(isValid).toBe(true);

      // Test with another Uint8Array input
      const message2 = new TextEncoder().encode('Hello again!');
      const signature2 = modifiedCurve.sign(message2, privateKey);
      const isValid2 = modifiedCurve.verify(signature2, message2, publicKey);
      expect(isValid2).toBe(true);
    });

    it('should maintain curve functionality after modification', () => {
      const Fp = Field(nobleSecp256k1.CURVE.p);
      const curveDef: Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'> = {
        Fp,
        n: nobleSecp256k1.CURVE.n,
        h: nobleSecp256k1.CURVE.h,
        a: nobleSecp256k1.CURVE.a,
        b: nobleSecp256k1.CURVE.b,
        Gx: nobleSecp256k1.CURVE.Gx,
        Gy: nobleSecp256k1.CURVE.Gy,
        lowS: true,
      };

      const curve = createCurve(curveDef, sha256, randomBytes);
      const modifiedCurve = modifyCurve(curve);

      // Test key generation
      const privateKey = modifiedCurve.utils.randomPrivateKey();
      const publicKey = modifiedCurve.getPublicKey(privateKey);
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(publicKey).toBeInstanceOf(Uint8Array);

      // Test signing and verification
      const message = new TextEncoder().encode('Test message');
      const signature = modifiedCurve.sign(message, privateKey);
      const isValid = modifiedCurve.verify(signature, message, publicKey);
      expect(isValid).toBe(true);
    });
  });
});
