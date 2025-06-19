import { describe, it, expect, vi } from 'vitest';
import { ed25519Sign } from '../ed25519Sign';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import tweetnacl from 'tweetnacl';

const message = new TextEncoder().encode('hello');

describe('ed25519Sign', () => {
  it('should sign a message with a valid private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const signature = ed25519Sign(curve, { message, privateKey });
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });

  it('should sign a message with a tweetnacl 64-byte private key', () => {
    const curve = createEd25519(randomBytes);
    const tweetnaclKeyPair = tweetnacl.sign.keyPair();
    const privateKey = new Uint8Array(tweetnaclKeyPair.secretKey);
    expect(privateKey.length).toBe(64);

    const signature = ed25519Sign(curve, { message, privateKey });
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);

    // Verify the signature with tweetnacl
    const isValid = tweetnacl.sign.detached.verify(
      message,
      signature,
      tweetnaclKeyPair.publicKey,
    );
    expect(isValid).toBe(true);
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(16); // Too short
    expect(() =>
      ed25519Sign(curve, { message, privateKey: invalidKey }),
    ).toThrow('Private key is invalid');
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(32); // All zeros
    expect(() =>
      ed25519Sign(curve, { message, privateKey: invalidKey }),
    ).toThrow('Private key is invalid');
  });

  it('should throw an error when recoverable is set to true', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    expect(() =>
      ed25519Sign(curve, { message, privateKey, recoverable: true }),
    ).toThrow('Recoverable signature is not supported');
  });

  it('should throw a generic error when curve.sign throws an error', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();

    // Mock the curve.sign to throw an error
    const originalSign = curve.sign;
    curve.sign = vi.fn().mockImplementation(() => {
      throw new Error('Internal signing error');
    });

    expect(() => ed25519Sign(curve, { message, privateKey })).toThrow(
      'Failed to sign message',
    );

    // Restore the original method
    curve.sign = originalSign;
  });

  it('should produce a signature that can be verified by Web Crypto API', async () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const signature = ed25519Sign(curve, { message, privateKey });

    // Import the public key into Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );

    // Verify the signature
    const isValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      signature,
      message,
    );

    expect(isValid).toBe(true);
  });

  it('should produce a signature from tweetnacl key that can be verified by Web Crypto API', async () => {
    const curve = createEd25519(randomBytes);
    const tweetnaclKeyPair = tweetnacl.sign.keyPair();
    const privateKey = new Uint8Array(tweetnaclKeyPair.secretKey);
    const signature = ed25519Sign(curve, { message, privateKey });

    // Import the tweetnacl public key into Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      tweetnaclKeyPair.publicKey,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );

    // Verify the signature
    const isValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      signature,
      message,
    );

    expect(isValid).toBe(true);
  });
});
