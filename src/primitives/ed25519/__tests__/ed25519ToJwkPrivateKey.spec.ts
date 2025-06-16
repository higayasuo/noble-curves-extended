import { describe, it, expect } from 'vitest';
import { ed25519ToJwkPrivateKey } from '../ed25519ToJwkPrivateKey';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { decodeBase64Url } from 'u8a-utils';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('ed25519ToJwkPrivateKey', () => {
  it('should convert a valid private key to JWK format', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
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
    expect(() => ed25519ToJwkPrivateKey(curve, invalidKey)).toThrow(
      'Ed25519 private key is invalid',
    );
  });

  it('should throw an error for all-zero private key', () => {
    const curve = createEd25519(randomBytes);
    const invalidKey = new Uint8Array(32); // All zeros
    expect(() => ed25519ToJwkPrivateKey(curve, invalidKey)).toThrow(
      'Ed25519 private key is invalid',
    );
  });
});
