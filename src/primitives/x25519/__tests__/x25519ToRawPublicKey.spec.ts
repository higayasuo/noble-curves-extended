import { describe, it, expect } from 'vitest';
import { createX25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { x25519ToRawPublicKey } from '../x25519ToRawPublicKey';
import { x25519ToJwkPublicKey } from '../x25519ToJwkPublicKey';
import type { JwkPublicKey } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519ToRawPublicKey', () => {
  it('should convert a valid JWK to a raw public key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const rawPublicKey = x25519ToRawPublicKey(curve, jwk);
    expect(rawPublicKey).toEqual(publicKey);
  });

  it('should throw an error for invalid kty', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, kty: 'EC' } as JwkPublicKey;
    expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: kty parameter must be OKP',
    );
  });

  it('should throw an error for invalid crv', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, crv: 'Ed25519' } as JwkPublicKey;
    expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: crv parameter must be X25519',
    );
  });

  it('should throw an error for missing x parameter', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const { x, ...invalidJwk } = jwk;
    expect(() =>
      x25519ToRawPublicKey(curve, invalidJwk as JwkPublicKey),
    ).toThrow('Invalid JWK: x parameter is missing');
  });

  it('should throw an error for non-string x parameter', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, x: 123 } as unknown as JwkPublicKey;
    expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: x parameter must be a string',
    );
  });

  it('should throw an error for invalid alg parameter', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, alg: 'ES256' } as JwkPublicKey;
    expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: alg parameter must be ECDH-ES',
    );
  });

  it('should throw an error for malformed Base64URL in x parameter', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, x: 'invalid-base64url!' } as JwkPublicKey;
    expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: malformed Base64URL in x parameter',
    );
  });

  it('should throw an error for invalid public key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = x25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = {
      ...jwk,
      x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    } as JwkPublicKey; // All zeros
    expect(() => x25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'X25519 public key is invalid',
    );
  });
});
