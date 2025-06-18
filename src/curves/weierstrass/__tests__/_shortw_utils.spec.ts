import { describe, it, expect } from 'vitest';
import { createCurve, createHmacFn, CurveDef } from '../_shortw_utils';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { secp256k1 as nobleSecp256k1 } from '@noble/curves/secp256k1';
import { Field } from '@noble/curves/abstract/modular';

describe('_shortw_utils', () => {
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
    it('should create a curve that can sign and verify messages', () => {
      const Fp = Field(nobleSecp256k1.CURVE.p);
      const curveDef: CurveDef = {
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

      // Generate a private key
      const privateKey = curve.utils.randomPrivateKey();
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);

      // Get the public key
      const publicKey = curve.getPublicKey(privateKey);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(33); // Compressed public key

      // Create a message to sign
      const message = Uint8Array.from(
        new TextEncoder().encode('Hello, world!'),
      );

      // Sign the message
      const signature = curve.sign(message, privateKey);

      // Verify the signature
      const isValid = curve.verify(signature, message, publicKey);
      expect(isValid).toBe(true);
    });

    it('should create a curve that can compute shared secrets', () => {
      const Fp = Field(nobleSecp256k1.CURVE.p);
      const curveDef: CurveDef = {
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

      // Generate two key pairs
      const alicePrivateKey = curve.utils.randomPrivateKey();
      const alicePublicKey = curve.getPublicKey(alicePrivateKey);

      const bobPrivateKey = curve.utils.randomPrivateKey();
      const bobPublicKey = curve.getPublicKey(bobPrivateKey);

      // Compute shared secrets
      const aliceSharedSecret = curve.getSharedSecret(
        alicePrivateKey,
        bobPublicKey,
      );
      const bobSharedSecret = curve.getSharedSecret(
        bobPrivateKey,
        alicePublicKey,
      );

      // Verify that both parties compute the same shared secret
      expect(aliceSharedSecret).toEqual(bobSharedSecret);
      expect(aliceSharedSecret).toBeInstanceOf(Uint8Array);
      expect(aliceSharedSecret.length).toBe(33); // Compressed point
    });
  });
});
