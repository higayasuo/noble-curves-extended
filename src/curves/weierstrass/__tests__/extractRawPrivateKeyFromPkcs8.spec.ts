import { describe, it, expect } from 'vitest';
import { extractRawPrivateKeyFromPkcs8 } from './extractRawPrivateKeyFromPkcs8';
import { ec as EC } from 'elliptic';
import { createPrivateKey } from 'crypto';

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

  it('should extract X25519 private key from PKCS8 format', async () => {
    // Generate X25519 key pair using Web Crypto API
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'X25519',
      },
      true,
      ['deriveKey', 'deriveBits'],
    );

    // Export private key in PKCS8 format
    const pkcs8PrivateKey = await crypto.subtle.exportKey(
      'pkcs8',
      (keyPair as CryptoKeyPair).privateKey,
    );
    // Extract raw private key
    const rawPrivateKey = extractRawPrivateKeyFromPkcs8(pkcs8PrivateKey);

    // X25519 private key should be 32 bytes
    expect(rawPrivateKey.byteLength).toBe(32);
  });

  it('should extract Ed25519 private key from PKCS8 format', async () => {
    // Generate Ed25519 key pair using Web Crypto API
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    // Export private key in PKCS8 format
    const pkcs8PrivateKey = await crypto.subtle.exportKey(
      'pkcs8',
      (keyPair as CryptoKeyPair).privateKey,
    );
    // Extract raw private key
    const rawPrivateKey = extractRawPrivateKeyFromPkcs8(pkcs8PrivateKey);

    // Ed25519 private key should be 32 bytes
    expect(rawPrivateKey.byteLength).toBe(32);
  });

  it('should extract secp256k1 private key from PKCS8 format', () => {
    // Generate secp256k1 key pair using elliptic
    const ec = new EC('secp256k1');
    const key = ec.genKeyPair();
    const privateKeyHex = key.getPrivate('hex');
    const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');

    // ASN.1 header + OID for sec1
    const sec1 = Buffer.concat([
      Buffer.from('302e0201010420', 'hex'),
      privateKeyBuffer,
      Buffer.from('a00706052b8104000a', 'hex'),
    ]);
    // Export as PKCS#8
    const pkcs8 = createPrivateKey({
      key: sec1,
      format: 'der',
      type: 'sec1',
    }).export({ format: 'der', type: 'pkcs8' });

    // Extract raw private key
    const rawPrivateKey = extractRawPrivateKeyFromPkcs8(pkcs8 as ArrayBuffer);
    // secp256k1 private key should be 32 bytes
    expect(rawPrivateKey.byteLength).toBe(32);
  });
});
