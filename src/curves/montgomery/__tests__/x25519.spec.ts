import { describe, it, expect } from 'vitest';
import { x25519 as nobleX25519 } from '@noble/curves/ed25519';
import { createX25519 } from '../x25519';
import { randomBytes } from '@noble/hashes/utils';
import { encodeBase64Url } from 'u8a-utils';
import { extractRawPrivateKeyFromPkcs8 } from '../../weierstrass/__tests__/extractRawPrivateKeyFromPkcs8';

describe('x25519 interoperability', () => {
  const ourX25519 = createX25519(randomBytes);

  describe('getSharedSecret', () => {
    describe('noble compatibility', () => {
      it('should compute the same shared secret when using our implementation with noble keys', () => {
        // Generate key pairs using noble implementation
        const alicePrivateKey = nobleX25519.utils.randomPrivateKey();
        const alicePublicKey = nobleX25519.getPublicKey(alicePrivateKey);
        const bobPrivateKey = nobleX25519.utils.randomPrivateKey();
        const bobPublicKey = nobleX25519.getPublicKey(bobPrivateKey);
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourX25519.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourX25519.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);
        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleX25519.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleX25519.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(nobleAliceSharedSecret);
        expect(bobSharedSecret).toEqual(nobleBobSharedSecret);
      });

      it('should compute the same shared secret when using noble implementation with our keys', () => {
        // Generate key pairs using our implementation
        const alicePrivateKey = ourX25519.utils.randomPrivateKey();
        const alicePublicKey = ourX25519.getPublicKey(alicePrivateKey);
        const bobPrivateKey = ourX25519.utils.randomPrivateKey();
        const bobPublicKey = ourX25519.getPublicKey(bobPrivateKey);
        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleX25519.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleX25519.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(nobleAliceSharedSecret).toEqual(nobleBobSharedSecret);
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourX25519.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourX25519.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(nobleAliceSharedSecret).toEqual(aliceSharedSecret);
        expect(nobleBobSharedSecret).toEqual(bobSharedSecret);
      });
    });

    describe('Web Crypto API compatibility', () => {
      it('should compute the same shared secret with Web Crypto API after generating keys with our implementation', async () => {
        // Generate key pairs using our implementation
        const alicePrivateKey = ourX25519.utils.randomPrivateKey();
        const alicePublicKey = ourX25519.getPublicKey(alicePrivateKey);
        const bobPrivateKey = ourX25519.utils.randomPrivateKey();
        const bobPublicKey = ourX25519.getPublicKey(bobPrivateKey);

        // Compute shared secret using our implementation
        const aliceSharedSecret = ourX25519.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourX25519.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Import keys into Web Crypto API
        const aliceJwkPrivateKey = {
          kty: 'OKP',
          crv: 'X25519',
          x: encodeBase64Url(alicePublicKey),
          d: encodeBase64Url(alicePrivateKey),
        };
        const aliceCryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          aliceJwkPrivateKey,
          {
            name: 'X25519',
          },
          false,
          ['deriveBits'],
        );
        const bobCryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          bobPublicKey,
          {
            name: 'X25519',
          },
          false,
          [],
        );

        // Compute shared secret using Web Crypto API
        const webCryptoSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'X25519',
            public: bobCryptoPublicKey,
          },
          aliceCryptoPrivateKey,
          256,
        );
        expect(new Uint8Array(webCryptoSharedSecret)).toEqual(
          aliceSharedSecret,
        );
      });

      it('should compute the same shared secret with our implementation after generating keys with Web Crypto API', async () => {
        // Generate key pairs using Web Crypto API
        const aliceKeyPair = await crypto.subtle.generateKey(
          {
            name: 'X25519',
          },
          true,
          ['deriveKey', 'deriveBits'],
        );
        const bobKeyPair = await crypto.subtle.generateKey(
          {
            name: 'X25519',
          },
          true,
          ['deriveKey', 'deriveBits'],
        );

        // Destructure keys
        const { publicKey: alicePublicKeyKey, privateKey: alicePrivateKeyKey } =
          aliceKeyPair as CryptoKeyPair;
        const { publicKey: bobPublicKeyKey, privateKey: bobPrivateKeyKey } =
          bobKeyPair as CryptoKeyPair;

        // Export public keys
        const alicePublicKey = new Uint8Array(
          await crypto.subtle.exportKey('raw', alicePublicKeyKey),
        );
        const bobPublicKey = new Uint8Array(
          await crypto.subtle.exportKey('raw', bobPublicKeyKey),
        );

        // Export private keys in pkcs8 format
        const alicePkcs8PrivateKey = await crypto.subtle.exportKey(
          'pkcs8',
          alicePrivateKeyKey,
        );
        const bobPkcs8PrivateKey = await crypto.subtle.exportKey(
          'pkcs8',
          bobPrivateKeyKey,
        );

        // Extract raw private keys
        const aliceRawPrivateKey = new Uint8Array(
          extractRawPrivateKeyFromPkcs8(alicePkcs8PrivateKey),
        );
        const bobRawPrivateKey = new Uint8Array(
          extractRawPrivateKeyFromPkcs8(bobPkcs8PrivateKey),
        );

        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourX25519.getSharedSecret(
          aliceRawPrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourX25519.getSharedSecret(
          bobRawPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Compute shared secret using Web Crypto API
        const webCryptoAliceSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'X25519',
            public: bobPublicKeyKey,
          },
          alicePrivateKeyKey,
          256,
        );
        const webCryptoBobSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'X25519',
            public: alicePublicKeyKey,
          },
          bobPrivateKeyKey,
          256,
        );
        expect(new Uint8Array(webCryptoAliceSharedSecret)).toEqual(
          new Uint8Array(webCryptoBobSharedSecret),
        );
        expect(new Uint8Array(webCryptoAliceSharedSecret)).toEqual(
          aliceSharedSecret,
        );
      });
    });
  });
});
