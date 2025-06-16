import { describe, it, expect } from 'vitest';
import { ed25519ToRawPrivateKey } from '../ed25519ToRawPrivateKey';
import { ed25519ToJwkPrivateKey } from '../ed25519ToJwkPrivateKey';
import { createEd25519 } from '../../../ed25519/ed25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('ed25519ToRawPrivateKey', () => {
  it('should convert a valid JWK to a raw private key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const rawPrivateKey = ed25519ToRawPrivateKey(curve, jwk);
    expect(rawPrivateKey).toEqual(privateKey);
  });

  it('should throw an error for invalid kty', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, kty: 'EC' };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: kty parameter must be OKP',
    );
  });

  it('should throw an error for invalid crv', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, crv: 'X25519' };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: crv parameter must be Ed25519',
    );
  });

  it('should throw an error for missing x parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const { x, ...invalidJwk } = jwk;
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
      'Invalid JWK: x parameter is missing',
    );
  });

  it('should throw an error for non-string x parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, x: 123 };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
      'Invalid JWK: x parameter must be a string',
    );
  });

  it('should throw an error for missing d parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const { d, ...invalidJwk } = jwk;
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
      'Invalid JWK: d parameter is missing',
    );
  });

  it('should throw an error for non-string d parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, d: 123 };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk as any)).toThrow(
      'Invalid JWK: d parameter must be a string',
    );
  });

  it('should throw an error for invalid alg parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, alg: 'ES256' };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: alg parameter must be EdDSA',
    );
  });

  it('should throw an error for malformed Base64URL in x parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, x: 'invalid-base64url!' };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: malformed Base64URL in x parameter',
    );
  });

  it('should throw an error for malformed Base64URL in d parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidJwk = { ...jwk, d: 'invalid-base64url!' };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: malformed Base64URL in d parameter',
    );
  });

  it('should throw an error for invalid public key (all zeros)', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidPublicKey = new Uint8Array(32); // All zeros
    const invalidJwk = {
      ...jwk,
      x: Buffer.from(invalidPublicKey).toString('base64url'),
    };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Ed25519 public key is invalid',
    );
  });

  it('should throw an error for invalid private key (all zeros)', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwk = ed25519ToJwkPrivateKey(curve, privateKey);
    const invalidPrivateKey = new Uint8Array(32); // All zeros
    const invalidJwk = {
      ...jwk,
      d: Buffer.from(invalidPrivateKey).toString('base64url'),
    };
    expect(() => ed25519ToRawPrivateKey(curve, invalidJwk)).toThrow(
      'Ed25519 private key is invalid',
    );
  });
});
