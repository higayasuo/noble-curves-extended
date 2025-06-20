import { describe, it, expect } from 'vitest';
import { ed25519ToJwkPublicKey } from '../ed25519ToJwkPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { decodeBase64Url } from 'u8a-utils';

describe('ed25519ToJwkPublicKey', () => {
  it('should convert a valid public key to JWK format', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    expect(jwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      x: expect.any(String),
    });
    // x should be a valid base64url string and decode to the original public key
    const decoded = decodeBase64Url(jwk.x);
    expect(decoded).toEqual(publicKey);
  });

  it('should throw an error for invalid public key length', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(16); // Too short
    expect(() => ed25519ToJwkPublicKey(curve, invalidKey)).toThrow(
      'Failed to convert public key to JWK',
    );
  });

  it('should generate a JWK that can be imported by Web Crypto API', async () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const importedKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'Ed25519',
      },
      false,
      [],
    );
    expect(importedKey).toBeDefined();
  });
});
