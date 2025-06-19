import { describe, it, expect } from 'vitest';
import { ed25519ToRawPublicKey } from '../ed25519ToRawPublicKey';
import { ed25519ToJwkPublicKey } from '../ed25519ToJwkPublicKey';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('ed25519ToRawPublicKey', () => {
  it('should convert a valid JWK to a raw public key', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const rawPublicKey = ed25519ToRawPublicKey(curve, jwk);
    expect(rawPublicKey).toEqual(publicKey);
  });

  it('should throw an error for invalid kty', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, kty: 'EC' };
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: kty parameter must be OKP',
    );
  });

  it('should throw an error for invalid crv', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, crv: 'X25519' };
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: crv parameter must be Ed25519',
    );
  });

  it('should throw an error for missing x parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const { x, ...invalidJwk } = jwk;
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk as any)).toThrow(
      'Invalid JWK: x parameter is missing',
    );
  });

  it('should throw an error for non-string x parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, x: 123 };
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk as any)).toThrow(
      'Invalid JWK: x parameter must be a string',
    );
  });

  it('should throw an error for invalid alg parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, alg: 'ES256' };
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: alg parameter must be EdDSA',
    );
  });

  it('should throw an error for malformed Base64URL in x parameter', () => {
    const curve = createEd25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey);
    const jwk = ed25519ToJwkPublicKey(curve, publicKey);
    const invalidJwk = { ...jwk, x: 'invalid-base64url!' };
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: malformed Base64URL in x parameter',
    );
  });

  it('should throw an error for invalid public key (all zeros)', () => {
    const curve = createEd25519(randomBytes);
    const invalidPublicKey = new Uint8Array(32); // All zeros
    const jwk = ed25519ToJwkPublicKey(
      curve,
      curve.getPublicKey(curve.utils.randomPrivateKey()),
    );
    const invalidJwk = {
      ...jwk,
      x: Buffer.from(invalidPublicKey).toString('base64url'),
    };
    expect(() => ed25519ToRawPublicKey(curve, invalidJwk)).toThrow(
      'Invalid JWK: public key is invalid',
    );
  });
});
