import { describe, it, expect } from 'vitest';
import { extractRawPrivateKeyFromPkcs8 } from './extractRawPrivateKeyFromPkcs8';

describe('extractRawPrivateKeyFromPkcs8', () => {
  it('should extract P-256 private key from PKCS8 format', async () => {
    // Generate P-256 key pair using Web Crypto API
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits'],
    );

    // Export private key in PKCS8 format
    const pkcs8PrivateKey = await crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey,
    );
    // Extract raw private key
    const rawPrivateKey = extractRawPrivateKeyFromPkcs8(pkcs8PrivateKey);

    // P-256 private key should be 32 bytes
    expect(rawPrivateKey.byteLength).toBe(32);
  });

  it('should extract P-384 private key from PKCS8 format', async () => {
    // Generate P-384 key pair using Web Crypto API
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-384',
      },
      true,
      ['deriveKey', 'deriveBits'],
    );

    // Export private key in PKCS8 format
    const pkcs8PrivateKey = await crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey,
    );

    // Extract raw private key
    const rawPrivateKey = extractRawPrivateKeyFromPkcs8(pkcs8PrivateKey);

    // P-384 private key should be 48 bytes
    expect(rawPrivateKey.byteLength).toBe(48);
  });

  it('should extract P-521 private key from PKCS8 format', async () => {
    // Generate P-521 key pair using Web Crypto API
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-521',
      },
      true,
      ['deriveKey', 'deriveBits'],
    );

    // Export private key in PKCS8 format
    const pkcs8PrivateKey = await crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey,
    );

    // Extract raw private key
    const rawPrivateKey = extractRawPrivateKeyFromPkcs8(pkcs8PrivateKey);

    // P-521 private key should be 66 bytes
    expect(rawPrivateKey.byteLength).toBe(66);
  });
});
