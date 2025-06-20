import { describe, it, expect } from 'vitest';
import { p384 as nobleP384 } from '@noble/curves/p384';
import { createP384, p384_CURVE } from '../p384';
import { randomBytes } from '@noble/hashes/utils';
import { encodeBase64Url } from 'u8a-utils';
import { extractRawPrivateKeyFromPkcs8 } from '../../../utils/extractRawPrivateKeyFromPkcs8';

describe('p384 interoperability', () => {
  const ourP384 = createP384(randomBytes);

  describe('curve parameters', () => {
    it('should have matching prime p values between our implementation and p384_CURVE', () => {
      expect(ourP384.CURVE.p).toEqual(p384_CURVE.p);
    });
  });

  describe('sign and verify', () => {
    describe('noble compatibility', () => {
      it('should verify signature created by our implementation using noble implementation', () => {
        // Generate key pair using our implementation
        const privateKey = ourP384.utils.randomPrivateKey();
        const publicKey = ourP384.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, P384!'),
        );
        const signature = ourP384.sign(message, privateKey, { prehash: true });
        // Verify with noble implementation
        const isValid = nobleP384.verify(signature, message, publicKey, {
          prehash: true,
        });
        expect(isValid).toBe(true);
      });

      it('should verify signature created by noble implementation using our implementation', () => {
        // Generate key pair using noble implementation
        const privateKey = nobleP384.utils.randomPrivateKey();
        const publicKey = nobleP384.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, P384!'),
        );
        const signature = nobleP384.sign(message, privateKey, {
          prehash: true,
        });
        // Verify with our implementation
        const isValid = ourP384.verify(signature, message, publicKey, {
          prehash: true,
        });
        expect(isValid).toBe(true);
      });
    });

    describe('Web Crypto API compatibility', () => {
      it('should verify signature with Web Crypto API after signing with our implementation', async () => {
        // Generate key pair using our implementation
        const privateKey = ourP384.utils.randomPrivateKey();
        const publicKey = ourP384.getPublicKey(privateKey, false);

        // Create message
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, P384!'),
        );
        const signature = ourP384
          .sign(message, privateKey, { prehash: true })
          .toCompactRawBytes();

        // Import public key into Web Crypto API
        const cryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          publicKey,
          {
            name: 'ECDSA',
            namedCurve: 'P-384',
          },
          false,
          ['verify'],
        );
        const isValidWebCrypto = await crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: 'SHA-384',
          },
          cryptoPublicKey,
          signature,
          message,
        );
        expect(isValidWebCrypto).toBe(true);
      });

      it('should verify signature with ourP384 after signing with Web Crypto API', async () => {
        // Generate key pair using our implementation
        const privateKey = ourP384.utils.randomPrivateKey();
        const publicKey = ourP384.getPublicKey(privateKey, false);

        // JWK for Web Crypto API
        const jwkPrivateKey = {
          kty: 'EC',
          crv: 'P-384',
          x: encodeBase64Url(publicKey.slice(1, 49)),
          y: encodeBase64Url(publicKey.slice(49)),
          d: encodeBase64Url(privateKey),
        };

        // Import private key into Web Crypto API
        const cryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          jwkPrivateKey,
          {
            name: 'ECDSA',
            namedCurve: 'P-384',
          },
          false,
          ['sign'],
        );

        // Create message
        const message = new TextEncoder().encode('Hello, P384!');

        // Sign with Web Crypto API
        const signature = await crypto.subtle.sign(
          {
            name: 'ECDSA',
            hash: 'SHA-384',
          },
          cryptoPrivateKey,
          message,
        );

        // Verify with ourP384
        const isValid = ourP384.verify(
          new Uint8Array(signature),
          message,
          publicKey,
          { prehash: true },
        );
        expect(isValid).toBe(true);
      });
    });
  });

  describe('getSharedSecret', () => {
    describe('noble compatibility', () => {
      it('should compute the same shared secret when using our implementation with noble keys', () => {
        // Generate key pairs using noble implementation
        const alicePrivateKey = nobleP384.utils.randomPrivateKey();
        const alicePublicKey = nobleP384.getPublicKey(alicePrivateKey);
        const bobPrivateKey = nobleP384.utils.randomPrivateKey();
        const bobPublicKey = nobleP384.getPublicKey(bobPrivateKey);
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourP384.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP384.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);
        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleP384.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleP384.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(nobleAliceSharedSecret);
        expect(bobSharedSecret).toEqual(nobleBobSharedSecret);
      });

      it('should compute the same shared secret when using noble implementation with our keys', () => {
        // Generate key pairs using our implementation
        const alicePrivateKey = ourP384.utils.randomPrivateKey();
        const alicePublicKey = ourP384.getPublicKey(alicePrivateKey);
        const bobPrivateKey = ourP384.utils.randomPrivateKey();
        const bobPublicKey = ourP384.getPublicKey(bobPrivateKey);
        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleP384.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleP384.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(nobleAliceSharedSecret).toEqual(nobleBobSharedSecret);
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourP384.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP384.getSharedSecret(
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
        const alicePrivateKey = ourP384.utils.randomPrivateKey();
        const alicePublicKey = ourP384.getPublicKey(alicePrivateKey, false);
        const bobPrivateKey = ourP384.utils.randomPrivateKey();
        const bobPublicKey = ourP384.getPublicKey(bobPrivateKey, false);

        // Compute shared secret using our implementation
        const aliceSharedSecret = ourP384.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP384.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Import keys into Web Crypto API
        const aliceCryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          {
            kty: 'EC',
            crv: 'P-384',
            x: encodeBase64Url(alicePublicKey.slice(1, 49)),
            y: encodeBase64Url(alicePublicKey.slice(49)),
            d: encodeBase64Url(alicePrivateKey),
          },
          {
            name: 'ECDH',
            namedCurve: 'P-384',
          },
          false,
          ['deriveBits'],
        );
        const bobCryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          bobPublicKey,
          {
            name: 'ECDH',
            namedCurve: 'P-384',
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
          384,
        );
        expect(new Uint8Array(webCryptoSharedSecret)).toEqual(
          aliceSharedSecret.slice(1),
        );
      });

      it('should compute the same shared secret with our implementation after generating keys with Web Crypto API', async () => {
        // Generate key pairs using Web Crypto API
        const aliceKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: 'P-384',
          },
          true,
          ['deriveKey', 'deriveBits'],
        );

        const bobKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: 'P-384',
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
        const aliceSharedSecret = ourP384.getSharedSecret(
          aliceRawPrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP384.getSharedSecret(
          bobRawPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Compute shared secret using Web Crypto API
        const webCryptoAliceSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: bobKeyPair.publicKey,
          },
          aliceKeyPair.privateKey,
          384,
        );

        const webCryptoBobSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: aliceKeyPair.publicKey,
          },
          bobKeyPair.privateKey,
          384,
        );

        // Verify that Web Crypto API computes the same shared secret
        expect(new Uint8Array(webCryptoAliceSharedSecret)).toEqual(
          new Uint8Array(webCryptoBobSharedSecret),
        );
        expect(new Uint8Array(webCryptoAliceSharedSecret)).toEqual(
          aliceSharedSecret.slice(1),
        );
      });
    });
  });
});
