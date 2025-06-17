import { describe, it, expect } from 'vitest';
import { p256 as nobleP256 } from '@noble/curves/p256';
import { createP256 } from '../p256';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { RandomBytes } from '../../types';
import { encodeBase64Url } from 'u8a-utils';
import { sha256 } from '@noble/hashes/sha2';

describe('p256 interoperability', () => {
  const randomBytes: RandomBytes = (bytesLength?: number) => {
    return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
  };
  const ourP256 = createP256(randomBytes);

  it('should verify signature created by custom implementation using noble implementation', () => {
    // Generate key pair using custom implementation
    const privateKey = ourP256.utils.randomPrivateKey();
    const publicKey = ourP256.getPublicKey(privateKey);

    // Create message using TextEncoder
    const message = Uint8Array.from(new TextEncoder().encode('Hello, P256!'));
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
    const message = Uint8Array.from(new TextEncoder().encode('Hello, P256!'));
    const signature = nobleP256.sign(message, privateKey);

    // Verify with custom implementation
    const isValid = ourP256.verify(signature, message, publicKey);
    expect(isValid).toBe(true);
  });

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

  it('should verify signature using Web Crypto API', async () => {
    // Generate key pair using our implementation
    const privateKey = ourP256.utils.randomPrivateKey();
    const publicKey = ourP256.getPublicKey(privateKey, false);

    const jwkPublicKey = {
      kty: 'EC',
      crv: 'P-256',
      x: encodeBase64Url(publicKey.slice(1, 33)),
      y: encodeBase64Url(publicKey.slice(33)),
    };

    // Create message using TextEncoder
    const message = Uint8Array.from(new TextEncoder().encode('Hello, P256!'));

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
