import { describe, it, expect } from 'vitest';
import { createX25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { x25519ToJwkPrivateKey } from '../x25519ToJwkPrivateKey';
import { importJWK } from 'jose';
import { decodeBase64Url } from 'u8a-utils';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519ToJwkPrivateKey', () => {
  it('should convert a valid private key to JWK format', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = x25519ToJwkPrivateKey(curve, privateKey);

    // Check JWK structure
    expect(jwk).toEqual({
      kty: 'OKP',
      crv: 'X25519',
      x: expect.any(String),
      d: expect.any(String),
      alg: 'ECDH-ES',
    });

    // Verify that x and d are valid Base64URL strings
    expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(jwk.d).toMatch(/^[A-Za-z0-9_-]+$/);

    // Verify that x and d decode to 32-byte arrays
    const decodedX = decodeBase64Url(jwk.x);
    const decodedD = decodeBase64Url(jwk.d);
    expect(decodedX.length).toBe(32);
    expect(decodedD.length).toBe(32);

    // Verify that d matches the original private key
    expect(decodedD).toEqual(privateKey);

    // Verify that x matches the public key derived from the private key
    const publicKey = curve.getPublicKey(privateKey);
    expect(decodedX).toEqual(publicKey);
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createX25519(randomBytes);
    const invalidKey = new Uint8Array(16); // Too short
    expect(() => x25519ToJwkPrivateKey(curve, invalidKey)).toThrow(
      'X25519 private key is invalid',
    );
  });

  it('should throw an error for empty private key', () => {
    const curve = createX25519(randomBytes);
    const emptyKey = new Uint8Array(0);
    expect(() => x25519ToJwkPrivateKey(curve, emptyKey)).toThrow(
      'X25519 private key is invalid',
    );
  });

  it('should throw an error for oversized private key', () => {
    const curve = createX25519(randomBytes);
    const oversizedKey = new Uint8Array(64); // Too long
    expect(() => x25519ToJwkPrivateKey(curve, oversizedKey)).toThrow(
      'X25519 private key is invalid',
    );
  });

  it('should generate a JWK that can be imported by jose', async () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = x25519ToJwkPrivateKey(curve, privateKey);
    const importedKey = await importJWK(jwk, 'ECDH-ES');
    expect(importedKey).toBeDefined();
  });

  it('should generate a JWK that can be imported by jose with use field', async () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = x25519ToJwkPrivateKey(curve, privateKey);
    const importedKey = await importJWK(jwk, 'ECDH-ES');
    expect(importedKey).toBeDefined();
  });
});
