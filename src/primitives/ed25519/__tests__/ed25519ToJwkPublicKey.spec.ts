import { describe, it, expect } from 'vitest';
import { ed25519ToJwkPublicKey } from '../ed25519ToJwkPublicKey';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { decodeBase64Url } from 'u8a-utils';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

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
      'Ed25519 public key is invalid',
    );
  });

  it('should throw an error for all-zero public key', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(32); // All zeros
    expect(() => ed25519ToJwkPublicKey(curve, invalidKey)).toThrow(
      'Ed25519 public key is invalid',
    );
  });
});
