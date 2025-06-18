import { describe, it, expect } from 'vitest';
import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519';
import { createEd25519 } from '../ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { encodeBase64Url } from 'u8a-utils';

// Note: Web Crypto API for Ed25519 uses 'Ed25519' as the namedCurve

describe('ed25519 interoperability', () => {
  const ourEd25519 = createEd25519(randomBytes);

  describe('sign and verify', () => {
    describe('noble compatibility', () => {
      it('should verify signature created by our implementation using noble implementation', () => {
        // Generate key pair using our implementation
        const privateKey = ourEd25519.utils.randomPrivateKey();
        const publicKey = ourEd25519.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, Ed25519!'),
        );
        const signature = ourEd25519.sign(message, privateKey);
        // Verify with noble implementation
        const isValid = nobleEd25519.verify(signature, message, publicKey);
        expect(isValid).toBe(true);
      });

      it('should verify signature created by noble implementation using our implementation', () => {
        // Generate key pair using noble implementation
        const privateKey = nobleEd25519.utils.randomPrivateKey();
        const publicKey = nobleEd25519.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, Ed25519!'),
        );
        const signature = nobleEd25519.sign(message, privateKey);
        // Verify with our implementation
        const isValid = ourEd25519.verify(signature, message, publicKey);
        expect(isValid).toBe(true);
      });
    });

    describe('Web Crypto API compatibility', () => {
      it('should verify signature with Web Crypto API after signing with our implementation', async () => {
        // Generate key pair using our implementation
        const privateKey = ourEd25519.utils.randomPrivateKey();
        const publicKey = ourEd25519.getPublicKey(privateKey);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, Ed25519!'),
        );
        const signature = ourEd25519.sign(message, privateKey);

        // Import public key into Web Crypto API
        const cryptoPublicKey = await crypto.subtle.importKey(
          'raw',
          publicKey,
          {
            name: 'Ed25519',
          },
          false,
          ['verify'],
        );
        const isValidWebCrypto = await crypto.subtle.verify(
          {
            name: 'Ed25519',
          },
          cryptoPublicKey,
          signature,
          message,
        );
        expect(isValidWebCrypto).toBe(true);
      });

      it('should verify signature with ourEd25519 after signing with Web Crypto API', async () => {
        // Generate key pair using our implementation
        const privateKey = ourEd25519.utils.randomPrivateKey();
        const publicKey = ourEd25519.getPublicKey(privateKey);

        // JWK for Web Crypto API
        const jwkPrivateKey = {
          kty: 'OKP',
          crv: 'Ed25519',
          x: encodeBase64Url(publicKey),
          d: encodeBase64Url(privateKey),
        };

        // Import private key into Web Crypto API
        const cryptoPrivateKey = await crypto.subtle.importKey(
          'jwk',
          jwkPrivateKey,
          {
            name: 'Ed25519',
          },
          false,
          ['sign'],
        );

        // Create message
        const message = new TextEncoder().encode('Hello, Ed25519!');

        // Sign with Web Crypto API
        const signature = await crypto.subtle.sign(
          {
            name: 'Ed25519',
          },
          cryptoPrivateKey,
          message,
        );

        // Verify with ourEd25519
        const isValid = ourEd25519.verify(
          new Uint8Array(signature),
          message,
          publicKey,
        );
        expect(isValid).toBe(true);
      });
    });
  });
});
