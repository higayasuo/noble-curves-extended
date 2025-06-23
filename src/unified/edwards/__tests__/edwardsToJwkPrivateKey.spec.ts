import { describe, it, expect } from 'vitest';
import { edwardsToJwkPrivateKey } from '../edwardsToJwkPrivateKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { decodeBase64Url } from 'u8a-utils';

describe('edwardsToJwkPrivateKey', () => {
  it('should convert a valid private key to JWK format', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = edwardsToJwkPrivateKey(curve, privateKey);
    expect(jwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      x: expect.any(String),
      d: expect.any(String),
    });
    // d and x should be valid base64url strings and decode to the original keys
    const decodedD = decodeBase64Url(jwk.d);
    const decodedX = decodeBase64Url(jwk.x);
    expect(decodedD).toEqual(privateKey);
    const publicKey = curve.getPublicKey(privateKey);
    expect(decodedX).toEqual(publicKey);
  });

  it('should throw an error for invalid private key length', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(16); // Too short
    expect(() => edwardsToJwkPrivateKey(curve, invalidKey)).toThrow(
      'Failed to convert private key to JWK',
    );
  });

  it('should generate a JWK that can be imported by Web Crypto API', async () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = edwardsToJwkPrivateKey(curve, privateKey);
    const importedKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'Ed25519',
      },
      false,
      ['sign'],
    );
    expect(importedKey).toBeDefined();
  });
});
