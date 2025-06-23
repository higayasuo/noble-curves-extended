import { describe, it, expect, vi } from 'vitest';
import { weierstrassVerify } from '../weierstrassVerify';
import { weierstrassSign } from '../weierstrassSign';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { weierstrassToJwkPrivateKey } from '../weierstrassToJwkPrivateKey';
import elliptic from 'elliptic';
import { sha256 } from '@noble/hashes/sha256';

const message = new TextEncoder().encode('hello');

const curves = [
  {
    name: 'P-256',
    createCurve: createP256,
    webCryptoAlgorithm: 'ES256' as const,
    hash: 'SHA-256' as const,
  },
  {
    name: 'P-384',
    createCurve: createP384,
    webCryptoAlgorithm: 'ES384' as const,
    hash: 'SHA-384' as const,
  },
  {
    name: 'P-521',
    createCurve: createP521,
    webCryptoAlgorithm: 'ES512' as const,
    hash: 'SHA-512' as const,
  },
  {
    name: 'secp256k1',
    createCurve: createSecp256k1,
    ellipticCurve: 'secp256k1' as const,
  },
];

describe('weierstrassVerify', () => {
  describe('basic tests', () => {
    it.each(curves)(
      'should verify a valid signature with recoverable: true for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const signature = weierstrassSign(curve, {
          message,
          privateKey,
          recovered: true,
        });
        expect(
          weierstrassVerify(curve, { signature, message, publicKey }),
        ).toBe(true);
      },
    );

    it.each(curves)(
      'should verify a valid signature with recoverable: false for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const signature = weierstrassSign(curve, {
          message,
          privateKey,
          recovered: false,
        });
        expect(
          weierstrassVerify(curve, { signature, message, publicKey }),
        ).toBe(true);
      },
    );
  });

  describe('compatibility tests', () => {
    describe('Web Crypto API compatibility', () => {
      it.each(curves.filter((c) => 'webCryptoAlgorithm' in c))(
        'should verify a signature created by Web Crypto API for $name',
        async ({ createCurve, hash }) => {
          const curve = createCurve(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const jwkPrivateKey = weierstrassToJwkPrivateKey(curve, privateKey);
          const publicKey = curve.getPublicKey(privateKey, false); // uncompressed for Web Crypto API

          // Import the private key into Web Crypto API
          const cryptoPrivateKey = await crypto.subtle.importKey(
            'jwk',
            jwkPrivateKey,
            { name: 'ECDSA', namedCurve: jwkPrivateKey.crv },
            false,
            ['sign'],
          );

          // Sign the message using Web Crypto API
          const signature = new Uint8Array(
            await crypto.subtle.sign(
              { name: 'ECDSA', hash: { name: hash! } },
              cryptoPrivateKey,
              message,
            ),
          );

          // Verify the signature using weierstrassVerify
          expect(
            weierstrassVerify(curve, { signature, message, publicKey }),
          ).toBe(true);
        },
      );
    });

    describe('elliptic compatibility', () => {
      it('should verify a signature created by elliptic for secp256k1', () => {
        const curve = createSecp256k1(randomBytes);
        const ec = new elliptic.ec('secp256k1');
        const ellipticKeyPair = ec.genKeyPair();
        const ellipticPrivateKey = Buffer.from(
          ellipticKeyPair.getPrivate().toArray('be', 32),
        );
        const ellipticPublicKey = new Uint8Array(
          ellipticKeyPair.getPublic().encode('array', false),
        );

        // Hash the message for compatibility with noble (prehash: true)
        const msgHash = sha256(message);
        // Sign with elliptic (using hashed message)
        const ellipticSignature = ec.sign(
          Buffer.from(msgHash),
          ellipticPrivateKey,
          { canonical: true },
        );
        const signature = new Uint8Array([
          ...ellipticSignature.r.toArray('be', 32),
          ...ellipticSignature.s.toArray('be', 32),
        ]);

        // Verify with weierstrassVerify
        expect(
          weierstrassVerify(curve, {
            signature,
            message,
            publicKey: ellipticPublicKey,
          }),
        ).toBe(true);
      });
    });
  });

  describe('invalid signature tests', () => {
    it.each(curves)(
      'should return false for an invalid signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const invalidSignature = new Uint8Array(64); // All zeros
        expect(
          weierstrassVerify(curve, {
            signature: invalidSignature,
            message,
            publicKey,
          }),
        ).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for a signature with wrong length for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const invalidSignature = new Uint8Array(32); // Wrong length
        expect(
          weierstrassVerify(curve, {
            signature: invalidSignature,
            message,
            publicKey,
          }),
        ).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for a signature with modified message for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const signature = weierstrassSign(curve, {
          message,
          privateKey,
          recovered: false,
        });

        const modifiedMessage = new TextEncoder().encode('hello world');
        expect(
          weierstrassVerify(curve, {
            signature,
            message: modifiedMessage,
            publicKey,
          }),
        ).toBe(false);
      },
    );

    it.each(curves)(
      'should return false for a signature with wrong public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey1 = curve.utils.randomPrivateKey();
        const privateKey2 = curve.utils.randomPrivateKey();
        const publicKey2 = curve.getPublicKey(privateKey2);
        const signature = weierstrassSign(curve, {
          message,
          privateKey: privateKey1,
          recovered: false,
        });

        expect(
          weierstrassVerify(curve, {
            signature,
            message,
            publicKey: publicKey2,
          }),
        ).toBe(false);
      },
    );
  });

  describe('error handling tests', () => {
    it.each(curves)(
      'should return false for an invalid public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = new Uint8Array(65); // All zeros (invalid)
        const signature = weierstrassSign(curve, {
          message,
          privateKey,
          recovered: false,
        });
        expect(
          weierstrassVerify(curve, { signature, message, publicKey }),
        ).toBe(false);
      },
    );

    it.each(curves)(
      'should return false when curve.verify throws an error for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);
        const signature = weierstrassSign(curve, {
          message,
          privateKey,
          recovered: false,
        });

        // Mock the curve.verify to throw an error
        const originalVerify = curve.verify;
        curve.verify = vi.fn().mockImplementation(() => {
          throw new Error('Internal verification error');
        });

        expect(
          weierstrassVerify(curve, { signature, message, publicKey }),
        ).toBe(false);

        // Restore the original method
        curve.verify = originalVerify;
      },
    );
  });
});
