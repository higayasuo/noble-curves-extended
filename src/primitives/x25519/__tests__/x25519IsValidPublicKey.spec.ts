import { describe, it, expect } from 'vitest';
import { createX25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { x25519IsValidPublicKey } from '../x25519IsValidPublicKey';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519IsValidPublicKey', () => {
  it('should return true for a valid public key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    expect(x25519IsValidPublicKey(curve, publicKey)).toBe(true);
  });

  it('should return false for an invalid public key (wrong length)', () => {
    const curve = createX25519(randomBytes);
    const invalidPublicKey = new Uint8Array(16); // Too short
    expect(x25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });

  it('should return false for an invalid public key (all zeros)', () => {
    const curve = createX25519(randomBytes);
    const invalidPublicKey = new Uint8Array(32).fill(0);
    expect(x25519IsValidPublicKey(curve, invalidPublicKey)).toBe(false);
  });

  it('should reject invalid public keys from RFC 7748 §6.1', () => {
    const curve = createX25519(randomBytes);

    // Small order points
    const smallOrderPoints = [
      // 0 (order 1)
      '0000000000000000000000000000000000000000000000000000000000000000',
      // 1 (order 1)
      '0100000000000000000000000000000000000000000000000000000000000000',
      // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      // p-1 (order 2)
      '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
      // p (order 4)
      '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
      // p+1 (order 1)
      '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee',
    ].map((hex) => Uint8Array.from(Buffer.from(hex, 'hex')));

    for (const point of smallOrderPoints) {
      console.log(point);
      expect(x25519IsValidPublicKey(curve, point)).toBe(false);
    }
  });
});
