import { describe, it, expect } from 'vitest';
import { weierstrassGetSharedSecret } from '../weierstrassGetSharedSecret';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { weierstrassToJwkPrivateKey } from '../weierstrassToJwkPrivateKey';
import elliptic from 'elliptic';
import { extractRawPrivateKeyFromPkcs8 } from '@/utils/extractRawPrivateKeyFromPkcs8';

type WebCryptoCurve = {
  name: 'P-256' | 'P-384' | 'P-521';
  createCurve: (randomBytes: () => Uint8Array) => any;
  webCryptoCurve: 'P-256' | 'P-384' | 'P-521';
  keyLength: number;
  keyByteLength: number;
};

type EllipticCurve = {
  name: string;
  createCurve: (randomBytes: () => Uint8Array) => any;
  ellipticCurve: 'secp256k1';
};

const webCryptoCurves: WebCryptoCurve[] = [
  {
    name: 'P-256',
    createCurve: createP256,
    webCryptoCurve: 'P-256',
    keyLength: 256,
    keyByteLength: 32,
  },
  {
    name: 'P-384',
    createCurve: createP384,
    webCryptoCurve: 'P-384',
    keyLength: 384,
    keyByteLength: 48,
  },
  {
    name: 'P-521',
    createCurve: createP521,
    webCryptoCurve: 'P-521',
    keyLength: 528,
    keyByteLength: 66,
  },
];

const ellipticCurves: EllipticCurve[] = [
  {
    name: 'secp256k1',
    createCurve: createSecp256k1,
    ellipticCurve: 'secp256k1',
  },
];

const allCurves = [...webCryptoCurves, ...ellipticCurves];

describe('weierstrassGetSharedSecret', () => {
  describe('basic validity tests', () => {
    it.each(allCurves)(
      'should compute valid shared secret for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const alicePrivateKey = curve.utils.randomPrivateKey();
        const alicePublicKey = curve.getPublicKey(alicePrivateKey);
        const bobPrivateKey = curve.utils.randomPrivateKey();
        const bobPublicKey = curve.getPublicKey(bobPrivateKey);

        const aliceSharedSecret = weierstrassGetSharedSecret(curve, {
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey,
        });
        const bobSharedSecret = weierstrassGetSharedSecret(curve, {
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey,
        });

        expect(aliceSharedSecret).toEqual(bobSharedSecret);
        expect(aliceSharedSecret).toBeInstanceOf(Uint8Array);
        expect(aliceSharedSecret.length).toBe(curve.CURVE.nByteLength);
      },
    );
  });

  describe('elliptic compatibility tests', () => {
    it('should compute the same shared secret with elliptic for secp256k1', () => {
      const curve = createSecp256k1(randomBytes);
      const ec = new elliptic.ec('secp256k1');

      // Generate key pairs using elliptic
      const alice = ec.genKeyPair();
      const bob = ec.genKeyPair();
      const alicePrivateKey = new Uint8Array(
        alice.getPrivate().toArray('be', 32),
      );
      const alicePublicKey = new Uint8Array(
        alice.getPublic().encode('array', false),
      );
      const bobPrivateKey = new Uint8Array(bob.getPrivate().toArray('be', 32));
      const bobPublicKey = new Uint8Array(
        bob.getPublic().encode('array', false),
      );

      // Compute shared secrets using our implementation
      const aliceSharedSecret = weierstrassGetSharedSecret(curve, {
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey,
      });
      const bobSharedSecret = weierstrassGetSharedSecret(curve, {
        privateKey: bobPrivateKey,
        publicKey: alicePublicKey,
      });

      expect(aliceSharedSecret).toEqual(bobSharedSecret);

      // Compute shared secrets using elliptic
      const ellipticAliceShared = new Uint8Array(
        alice.derive(bob.getPublic()).toArray('be', 32),
      );
      const ellipticBobShared = new Uint8Array(
        bob.derive(alice.getPublic()).toArray('be', 32),
      );

      expect(ellipticAliceShared).toEqual(ellipticBobShared);
      expect(aliceSharedSecret).toEqual(ellipticAliceShared);
      expect(bobSharedSecret).toEqual(ellipticBobShared);
    });

    it('should compute the same shared secret with elliptic using our secp256k1 keys', () => {
      const curve = createSecp256k1(randomBytes);
      const ec = new elliptic.ec('secp256k1');

      // Generate key pairs using our implementation
      const alicePrivateKey = curve.utils.randomPrivateKey();
      const alicePublicKey = curve.getPublicKey(alicePrivateKey, false); // uncompressed
      const bobPrivateKey = curve.utils.randomPrivateKey();
      const bobPublicKey = curve.getPublicKey(bobPrivateKey, false); // uncompressed

      // Import keys into elliptic
      const aliceKey = ec.keyFromPrivate(
        Buffer.from(alicePrivateKey).toString('hex'),
        'hex',
      );
      const bobKey = ec.keyFromPrivate(
        Buffer.from(bobPrivateKey).toString('hex'),
        'hex',
      );
      const alicePub = aliceKey.getPublic();
      const bobPub = bobKey.getPublic();

      // Compute shared secrets using our implementation
      const aliceSharedSecret = weierstrassGetSharedSecret(curve, {
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey,
      });
      const bobSharedSecret = weierstrassGetSharedSecret(curve, {
        privateKey: bobPrivateKey,
        publicKey: alicePublicKey,
      });

      expect(aliceSharedSecret).toEqual(bobSharedSecret);

      // Compute shared secrets using elliptic
      const ellipticAliceShared = new Uint8Array(
        aliceKey.derive(bobPub).toArray('be', 32),
      );
      const ellipticBobShared = new Uint8Array(
        bobKey.derive(alicePub).toArray('be', 32),
      );

      expect(ellipticAliceShared).toEqual(ellipticBobShared);
      expect(aliceSharedSecret).toEqual(ellipticAliceShared);
      expect(bobSharedSecret).toEqual(ellipticBobShared);
    });
  });

  describe('Web Crypto API compatibility tests', () => {
    it.each(webCryptoCurves)(
      'should compute the same shared secret with Web Crypto API for $name',
      async ({
        name,
        createCurve,
        webCryptoCurve,
        keyLength,
        keyByteLength,
      }) => {
        const curve = createCurve(randomBytes);
        const alicePrivateKey = curve.utils.randomPrivateKey();
        const alicePublicKey = curve.getPublicKey(alicePrivateKey, false); // uncompressed
        const bobPrivateKey = curve.utils.randomPrivateKey();
        const bobPublicKey = curve.getPublicKey(bobPrivateKey, false); // uncompressed

        // Compute shared secret using our implementation
        const aliceSharedSecret = weierstrassGetSharedSecret(curve, {
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey,
        });
        const bobSharedSecret = weierstrassGetSharedSecret(curve, {
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey,
        });

        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Import keys into Web Crypto API
        const aliceJwkPrivateKey = weierstrassToJwkPrivateKey(
          curve,
          keyByteLength,
          name,
          name === 'P-256' ? 'ES256' : name === 'P-384' ? 'ES384' : 'ES512',
          alicePrivateKey,
        );

        const aliceCryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          aliceJwkPrivateKey,
          {
            name: 'ECDH',
            namedCurve: webCryptoCurve,
          },
          false,
          ['deriveBits'],
        );

        const bobCryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          bobPublicKey,
          {
            name: 'ECDH',
            namedCurve: webCryptoCurve,
          },
          false,
          [],
        );

        // Compute shared secret using Web Crypto API
        const webCryptoSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: bobCryptoPublicKey,
          },
          aliceCryptoPrivateKey,
          keyLength,
        );

        // Verify that Web Crypto API computes the same shared secret
        expect(new Uint8Array(webCryptoSharedSecret)).toEqual(
          aliceSharedSecret,
        );
      },
    );

    it.each(webCryptoCurves)(
      'should compute the same shared secret with our implementation after generating keys with Web Crypto API for $name',
      async ({ createCurve, webCryptoCurve, keyLength }) => {
        const curve = createCurve(randomBytes);

        // Generate key pairs using Web Crypto API
        const aliceKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: webCryptoCurve,
          },
          true,
          ['deriveKey', 'deriveBits'],
        );

        const bobKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: webCryptoCurve,
          },
          true,
          ['deriveKey', 'deriveBits'],
        );

        // Export public keys
        const alicePublicKey = new Uint8Array(
          await crypto.subtle.exportKey('raw', aliceKeyPair.publicKey),
        );
        const bobPublicKey = new Uint8Array(
          await crypto.subtle.exportKey('raw', bobKeyPair.publicKey),
        );

        // Export private keys in pkcs8 format
        const alicePkcs8PrivateKey = await crypto.subtle.exportKey(
          'pkcs8',
          aliceKeyPair.privateKey,
        );
        const bobPkcs8PrivateKey = await crypto.subtle.exportKey(
          'pkcs8',
          bobKeyPair.privateKey,
        );

        // Extract raw private keys
        const aliceRawPrivateKey = new Uint8Array(
          extractRawPrivateKeyFromPkcs8(alicePkcs8PrivateKey),
        );
        const bobRawPrivateKey = new Uint8Array(
          extractRawPrivateKeyFromPkcs8(bobPkcs8PrivateKey),
        );

        // Compute shared secrets using our implementation
        const aliceSharedSecret = weierstrassGetSharedSecret(curve, {
          privateKey: aliceRawPrivateKey,
          publicKey: bobPublicKey,
        });
        const bobSharedSecret = weierstrassGetSharedSecret(curve, {
          privateKey: bobRawPrivateKey,
          publicKey: alicePublicKey,
        });

        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Compute shared secret using Web Crypto API
        const webCryptoAliceSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: bobKeyPair.publicKey,
          },
          aliceKeyPair.privateKey,
          keyLength,
        );

        const webCryptoBobSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: aliceKeyPair.publicKey,
          },
          bobKeyPair.privateKey,
          keyLength,
        );

        // Verify that Web Crypto API computes the same shared secret
        expect(new Uint8Array(webCryptoAliceSharedSecret)).toEqual(
          new Uint8Array(webCryptoBobSharedSecret),
        );
        expect(new Uint8Array(webCryptoAliceSharedSecret)).toEqual(
          aliceSharedSecret,
        );
      },
    );
  });

  describe('error handling tests', () => {
    it.each(allCurves)(
      'should throw an error for invalid private key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const validPrivateKey = curve.utils.randomPrivateKey();
        const validPublicKey = curve.getPublicKey(validPrivateKey);
        const invalidPrivateKey = new Uint8Array(16); // Wrong length

        expect(() =>
          weierstrassGetSharedSecret(curve, {
            privateKey: invalidPrivateKey,
            publicKey: validPublicKey,
          }),
        ).toThrow('Failed to compute shared secret');
      },
    );

    it.each(allCurves)(
      'should throw an error for invalid public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const validPrivateKey = curve.utils.randomPrivateKey();
        const invalidPublicKey = new Uint8Array(32); // Wrong length

        expect(() =>
          weierstrassGetSharedSecret(curve, {
            privateKey: validPrivateKey,
            publicKey: invalidPublicKey,
          }),
        ).toThrow('Failed to compute shared secret');
      },
    );

    it.each(allCurves)(
      'should throw an error when curve.getSharedSecret throws an error for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey);

        // Mock the curve.getSharedSecret to throw an error
        const originalGetSharedSecret = curve.getSharedSecret;
        curve.getSharedSecret = () => {
          throw new Error('Internal shared secret error');
        };

        expect(() =>
          weierstrassGetSharedSecret(curve, {
            privateKey,
            publicKey,
          }),
        ).toThrow('Failed to compute shared secret');

        // Restore the original method
        curve.getSharedSecret = originalGetSharedSecret;
      },
    );
  });
});
