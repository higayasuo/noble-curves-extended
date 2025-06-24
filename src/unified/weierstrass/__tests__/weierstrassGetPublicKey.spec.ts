import { describe, it, expect, vi } from 'vitest';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { weierstrassGetPublicKey } from '../weierstrassGetPublicKey';
import { weierstrassRandomPrivateKey } from '../weierstrassRandomPrivateKey';
import { randomBytes } from '@noble/hashes/utils';

describe('weierstrassGetPublicKey', () => {
  const curves = [
    {
      name: 'P-256',
      createCurve: createP256,
      expectedLength: 33,
      expectedUncompressedLength: 65,
    },
    {
      name: 'P-384',
      createCurve: createP384,
      expectedLength: 49,
      expectedUncompressedLength: 97,
    },
    {
      name: 'P-521',
      createCurve: createP521,
      expectedLength: 67,
      expectedUncompressedLength: 133,
    },
    {
      name: 'secp256k1',
      createCurve: createSecp256k1,
      expectedLength: 33,
      expectedUncompressedLength: 65,
    },
  ];

  describe('successful public key generation tests', () => {
    it.each(curves)(
      'should generate a valid compressed public key for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        const publicKey = weierstrassGetPublicKey(curve, privateKey);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(expectedLength);
        // Compressed public keys start with 0x02 or 0x03
        expect([0x02, 0x03]).toContain(publicKey[0]);
      },
    );

    it.each(curves)(
      'should generate a valid compressed public key when compressed=true for $name',
      ({ createCurve, expectedLength }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        const publicKey = weierstrassGetPublicKey(curve, privateKey, true);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(expectedLength);
        expect([0x02, 0x03]).toContain(publicKey[0]);
      },
    );

    it.each(curves)(
      'should generate a valid uncompressed public key when compressed=false for $name',
      ({ createCurve, expectedUncompressedLength }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);
        const publicKey = weierstrassGetPublicKey(curve, privateKey, false);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(expectedUncompressedLength);
        expect(publicKey[0]).toBe(0x04);
      },
    );

    it.each(curves)(
      'should generate different public keys for different private keys for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey1 = weierstrassRandomPrivateKey(curve);
        const privateKey2 = weierstrassRandomPrivateKey(curve);

        const publicKey1 = weierstrassGetPublicKey(curve, privateKey1);
        const publicKey2 = weierstrassGetPublicKey(curve, privateKey2);

        expect(publicKey1).not.toEqual(publicKey2);
      },
    );

    it.each(curves)(
      'should generate the same public key for the same private key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);

        const publicKey1 = weierstrassGetPublicKey(curve, privateKey);
        const publicKey2 = weierstrassGetPublicKey(curve, privateKey);

        expect(publicKey1).toEqual(publicKey2);
      },
    );
  });

  describe('invalid input tests', () => {
    it.each(curves)(
      'should throw an error for private key with wrong length for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const invalidPrivateKey = new Uint8Array(16); // Too short

        expect(() => weierstrassGetPublicKey(curve, invalidPrivateKey)).toThrow(
          'Failed to get public key',
        );
      },
    );

    it.each(curves)(
      'should throw an error for empty private key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const emptyPrivateKey = new Uint8Array(0);

        expect(() => weierstrassGetPublicKey(curve, emptyPrivateKey)).toThrow(
          'Failed to get public key',
        );
      },
    );
  });

  describe('error handling tests', () => {
    it.each(curves)(
      'should throw an error when curve.getPublicKey fails for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = weierstrassRandomPrivateKey(curve);

        // Mock getPublicKey to throw an error
        const originalGetPublicKey = curve.getPublicKey;
        curve.getPublicKey = vi.fn().mockImplementation(() => {
          throw new Error('Public key generation failed');
        });

        expect(() => weierstrassGetPublicKey(curve, privateKey)).toThrow(
          'Failed to get public key',
        );

        // Restore original method
        curve.getPublicKey = originalGetPublicKey;
      },
    );
  });
});
