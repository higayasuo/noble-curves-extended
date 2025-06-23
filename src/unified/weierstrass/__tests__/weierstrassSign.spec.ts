import { describe, it, expect, vi } from 'vitest';
import { weierstrassSign } from '../weierstrassSign';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import elliptic from 'elliptic';
import { sha256 } from '@noble/hashes/sha256';

const message = new TextEncoder().encode('hello');

describe('weierstrassSign', () => {
  const curves = [
    {
      name: 'P-256',
      createCurve: () => createP256(randomBytes),
      signatureLength: 64,
      webCryptoName: 'ECDSA',
      webCryptoNamedCurve: 'P-256',
      webCryptoHash: 'SHA-256',
    },
    {
      name: 'P-384',
      createCurve: () => createP384(randomBytes),
      signatureLength: 96,
      webCryptoName: 'ECDSA',
      webCryptoNamedCurve: 'P-384',
      webCryptoHash: 'SHA-384',
    },
    {
      name: 'P-521',
      createCurve: () => createP521(randomBytes),
      signatureLength: 132,
      webCryptoName: 'ECDSA',
      webCryptoNamedCurve: 'P-521',
      webCryptoHash: 'SHA-512',
    },
    {
      name: 'secp256k1',
      createCurve: () => createSecp256k1(randomBytes),
      signatureLength: 64,
      ellipticCurve: 'secp256k1',
    },
  ];

  describe('basic tests', () => {
    it.each(curves)(
      'should sign a message with a valid private key for $name',
      ({ createCurve, signatureLength }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const signature = weierstrassSign(curve, { message, privateKey });
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(signatureLength);
      },
    );
  });

  describe('compatibility tests', () => {
    describe('Web Crypto API compatibility', () => {
      it.each(curves.filter((c) => c.name !== 'secp256k1'))(
        'should produce a signature that can be verified by Web Crypto API for $name',
        async ({ createCurve, webCryptoNamedCurve, webCryptoHash }) => {
          const curve = createCurve();
          const privateKey = curve.utils.randomPrivateKey();
          const publicKey = curve.getPublicKey(privateKey, false); // uncompressed
          const signature = weierstrassSign(curve, { message, privateKey });

          // Import the public key into Web Crypto API
          const cryptoKey = await crypto.subtle.importKey(
            'raw',
            publicKey,
            {
              name: 'ECDSA',
              namedCurve: webCryptoNamedCurve as 'P-256' | 'P-384' | 'P-521',
            },
            false,
            ['verify'],
          );

          // Verify the signature
          const isValid = await crypto.subtle.verify(
            {
              name: 'ECDSA',
              hash: webCryptoHash as 'SHA-256' | 'SHA-384' | 'SHA-512',
            },
            cryptoKey,
            signature,
            message,
          );

          expect(isValid).toBe(true);
        },
      );
    });

    describe('elliptic compatibility', () => {
      it('should produce a signature that can be verified by elliptic for secp256k1', () => {
        const curve = createSecp256k1(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey, false); // uncompressed
        const signature = weierstrassSign(curve, { message, privateKey });

        // Create elliptic curve instance
        const ec = new elliptic.ec('secp256k1');

        // Import the public key into elliptic
        const key = ec.keyFromPublic(publicKey, 'hex'); // Remove 0x04 prefix

        // Hash the message with SHA-256 for elliptic verification
        const hashedMessage = sha256(message);

        // Verify the signature
        const isValid = key.verify(hashedMessage, {
          r: signature.slice(0, 32),
          s: signature.slice(32, 64),
        });

        expect(isValid).toBe(true);
      });
    });
  });

  describe('recoverable signature tests', () => {
    it.each(curves)(
      'should recover public key from recoverable signature for $name',
      ({ createCurve, signatureLength }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        const expectedPublicKey = curve.getPublicKey(privateKey, false); // uncompressed
        const signature = weierstrassSign(curve, {
          message,
          privateKey,
          recovered: true,
        });
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(signatureLength + 1); // +1 for recovery byte

        // Extract recovery byte and signature
        const recoveryBit = signature[signature.length - 1];
        const signatureWithoutRecovery = signature.slice(0, -1);

        // Hash the message since weierstrassSign uses prehash: true
        const messageHash = curve.CURVE.hash(message);

        // Recovered uncompressed public key from signature
        const recoveredPublicKey = curve.Signature.fromCompact(
          signatureWithoutRecovery,
        )
          .addRecoveryBit(recoveryBit)
          .recoverPublicKey(messageHash)
          .toRawBytes(false);

        expect(recoveredPublicKey).toEqual(expectedPublicKey);
      },
    );
  });

  describe('invalid input tests', () => {
    it.each(curves)(
      'should throw an error for invalid private key length in $name',
      ({ createCurve }) => {
        const curve = createCurve();
        const invalidKey = new Uint8Array(16); // Too short
        expect(() =>
          weierstrassSign(curve, { message, privateKey: invalidKey }),
        ).toThrow('Failed to sign message');
      },
    );

    it.each(curves)(
      'should throw an error for null private key in $name',
      ({ createCurve }) => {
        const curve = createCurve();
        expect(() =>
          weierstrassSign(curve, { message, privateKey: null as any }),
        ).toThrow('Failed to sign message');
      },
    );

    it.each(curves)(
      'should throw an error for undefined private key in $name',
      ({ createCurve }) => {
        const curve = createCurve();
        expect(() =>
          weierstrassSign(curve, { message, privateKey: undefined as any }),
        ).toThrow('Failed to sign message');
      },
    );

    it.each(curves)(
      'should throw an error for null message in $name',
      ({ createCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        expect(() =>
          weierstrassSign(curve, { message: null as any, privateKey }),
        ).toThrow('Failed to sign message');
      },
    );

    it.each(curves)(
      'should throw an error for undefined message in $name',
      ({ createCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();
        expect(() =>
          weierstrassSign(curve, { message: undefined as any, privateKey }),
        ).toThrow('Failed to sign message');
      },
    );
  });

  describe('error handling tests', () => {
    it.each(curves)(
      'should throw a generic error when curve.sign throws an error for $name',
      ({ createCurve }) => {
        const curve = createCurve();
        const privateKey = curve.utils.randomPrivateKey();

        // Mock the curve.sign to throw an error
        const originalSign = curve.sign;
        curve.sign = vi.fn().mockImplementation(() => {
          throw new Error('Internal signing error');
        });

        expect(() => weierstrassSign(curve, { message, privateKey })).toThrow(
          'Failed to sign message',
        );

        // Restore the original method
        curve.sign = originalSign;
      },
    );
  });
});
