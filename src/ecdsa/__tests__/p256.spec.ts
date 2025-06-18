import { describe, it, expect } from 'vitest';
import { p256 as nobleP256 } from '@noble/curves/p256';
import { createP256 } from '../p256';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { RandomBytes } from '../../types';
import { encodeBase64Url } from 'u8a-utils';
import { extractRawPrivateKeyFromPkcs8 } from './extractRawPrivateKeyFromPkcs8';

describe('p256 interoperability', () => {
  const randomBytes: RandomBytes = (bytesLength?: number) => {
    return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
  };
  const ourP256 = createP256(randomBytes);

  describe('sign and verify', () => {
    describe('noble compatibility', () => {
      it('should verify signature created by custom implementation using noble implementation', () => {
        // Generate key pair using custom implementation
        const privateKey = ourP256.utils.randomPrivateKey();
        const publicKey = ourP256.getPublicKey(privateKey);

        // Create message using TextEncoder
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, P256!'),
        );
        const signature = ourP256.sign(message, privateKey);

        // Verify with noble implementation
        const isValid = nobleP256.verify(signature, message, publicKey);
        expect(isValid).toBe(true);
      });

      it('should verify signature created by noble implementation using custom implementation', () => {
        // Generate key pair using noble implementation
        const privateKey = nobleP256.utils.randomPrivateKey();
        const publicKey = nobleP256.getPublicKey(privateKey);

        // Create message using TextEncoder
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, P256!'),
        );
        const signature = nobleP256.sign(message, privateKey);

        // Verify with custom implementation
        const isValid = ourP256.verify(signature, message, publicKey);
        expect(isValid).toBe(true);
      });
    });

    describe('Web Crypto API compatibility', () => {
      it('should verify signature with Web Crypto API after signing with our implementation', async () => {
        // Generate key pair using our implementation
        const privateKey = ourP256.utils.randomPrivateKey();
        const publicKey = ourP256.getPublicKey(privateKey, false);

        // Create message using TextEncoder
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, P256!'),
        );

        const signature = ourP256
          .sign(message, privateKey, {
            prehash: true,
          })
          .toCompactRawBytes();

        const cryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          publicKey,
          {
            name: 'ECDSA',
            namedCurve: 'P-256',
          },
          false,
          ['verify'],
        );
        const isValidWebCrypto = await crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: 'SHA-256',
          },
          cryptoPublicKey,
          signature,
          message,
        );
        expect(isValidWebCrypto).toBe(true);
      });

      it('should verify signature with ourP256 after signing with Web Crypto API', async () => {
        // Generate key pair using our implementation
        const privateKey = ourP256.utils.randomPrivateKey();
        const publicKey = ourP256.getPublicKey(privateKey, false);

        const jwkPrivateKey = {
          kty: 'EC',
          crv: 'P-256',
          x: encodeBase64Url(publicKey.slice(1, 33)),
          y: encodeBase64Url(publicKey.slice(33)),
          d: encodeBase64Url(privateKey),
        };

        // Import private key into Web Crypto API
        const cryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          jwkPrivateKey,
          {
            name: 'ECDSA',
            namedCurve: 'P-256',
          },
          false,
          ['sign'],
        );

        // Create message
        const message = new TextEncoder().encode('Hello, P256!');

        // Sign with Web Crypto API
        const signature = await crypto.subtle.sign(
          {
            name: 'ECDSA',
            hash: 'SHA-256',
          },
          cryptoPrivateKey,
          message,
        );

        // Verify with ourP256
        const isValid = ourP256.verify(
          new Uint8Array(signature),
          message,
          publicKey,
          {
            prehash: true,
          },
        );
        expect(isValid).toBe(true);
      });
    });
  });

  describe('getSharedSecret', () => {
    describe('noble compatibility', () => {
      it('should compute the same shared secret when using custom implementation with noble keys', () => {
        // Generate key pairs using noble implementation
        const alicePrivateKey = nobleP256.utils.randomPrivateKey();
        const alicePublicKey = nobleP256.getPublicKey(alicePrivateKey);

        const bobPrivateKey = nobleP256.utils.randomPrivateKey();
        const bobPublicKey = nobleP256.getPublicKey(bobPrivateKey);

        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourP256.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP256.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );

        // Verify that both parties compute the same shared secret
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Verify with noble implementation
        const nobleAliceSharedSecret = nobleP256.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleP256.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );

        // Verify that our implementation matches noble's
        expect(aliceSharedSecret).toEqual(nobleAliceSharedSecret);
        expect(bobSharedSecret).toEqual(nobleBobSharedSecret);
      });

      it('should compute the same shared secret when using noble implementation with custom keys', () => {
        // Generate key pairs using our implementation
        const alicePrivateKey = ourP256.utils.randomPrivateKey();
        const alicePublicKey = ourP256.getPublicKey(alicePrivateKey);

        const bobPrivateKey = ourP256.utils.randomPrivateKey();
        const bobPublicKey = ourP256.getPublicKey(bobPrivateKey);

        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleP256.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleP256.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );

        // Verify that both parties compute the same shared secret
        expect(nobleAliceSharedSecret).toEqual(nobleBobSharedSecret);

        // Verify with our implementation
        const aliceSharedSecret = ourP256.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP256.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );

        // Verify that noble implementation matches ours
        expect(nobleAliceSharedSecret).toEqual(aliceSharedSecret);
        expect(nobleBobSharedSecret).toEqual(bobSharedSecret);
      });
    });

    describe('Web Crypto API compatibility', () => {
      it('should compute the same shared secret with Web Crypto API after generating keys with our implementation', async () => {
        // Generate key pairs using our implementation
        const alicePrivateKey = ourP256.utils.randomPrivateKey();
        const alicePublicKey = ourP256.getPublicKey(alicePrivateKey, false);

        const bobPrivateKey = ourP256.utils.randomPrivateKey();
        const bobPublicKey = ourP256.getPublicKey(bobPrivateKey, false);

        // Compute shared secret using our implementation
        const aliceSharedSecret = ourP256.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP256.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );

        // Verify that both parties compute the same shared secret
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Import keys into Web Crypto API
        const aliceJwkPrivateKey = {
          kty: 'EC',
          crv: 'P-256',
          x: encodeBase64Url(alicePublicKey.slice(1, 33)),
          y: encodeBase64Url(alicePublicKey.slice(33)),
          d: encodeBase64Url(alicePrivateKey),
        };

        const aliceCryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          aliceJwkPrivateKey,
          {
            name: 'ECDH',
            namedCurve: 'P-256',
          },
          false,
          ['deriveBits'],
        );

        const bobCryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          bobPublicKey,
          {
            name: 'ECDH',
            namedCurve: 'P-256',
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
          256,
        );

        // Verify that Web Crypto API computes the same shared secret
        expect(new Uint8Array(webCryptoSharedSecret)).toEqual(
          aliceSharedSecret.slice(1),
        );
      });

      it('should compute the same shared secret with our implementation after generating keys with Web Crypto API', async () => {
        // Generate key pairs using Web Crypto API
        const aliceKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: 'P-256',
          },
          true,
          ['deriveKey', 'deriveBits'],
        );

        const bobKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: 'P-256',
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
        const aliceSharedSecret = ourP256.getSharedSecret(
          aliceRawPrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourP256.getSharedSecret(
          bobRawPrivateKey,
          alicePublicKey,
        );

        // Verify that both parties compute the same shared secret
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Compute shared secret using Web Crypto API
        const webCryptoAliceSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: bobKeyPair.publicKey,
          },
          aliceKeyPair.privateKey,
          256,
        );

        const webCryptoBobSharedSecret = await crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            public: aliceKeyPair.publicKey,
          },
          bobKeyPair.privateKey,
          256,
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
