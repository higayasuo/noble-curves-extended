import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { P256 } from '../P256';

const p256 = new P256(randomBytes);

describe('P256', () => {
  it('should construct with correct identifiers', () => {
    expect(p256.curveName).toBe('P-256');
    expect(p256.signatureAlgorithmName).toBe('ES256');
    expect(p256.keyByteLength).toBe(32);
    expect(typeof p256.getCurve).toBe('function');
  });

  it('should generate a valid random private key', () => {
    const sk = p256.randomPrivateKey();
    expect(sk).toBeInstanceOf(Uint8Array);
    expect(sk.length).toBe(32);
  });

  it('should derive compressed public key from private key', () => {
    const sk = p256.randomPrivateKey();
    const pk = p256.getPublicKey(sk);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(33);
    expect([0x02, 0x03]).toContain(pk[0]);
  });

  it('should derive uncompressed public key from private key', () => {
    const sk = p256.randomPrivateKey();
    const pk = p256.getPublicKey(sk, false);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(65);
    expect(pk[0]).toBe(0x04);
  });

  it('should sign and verify message', () => {
    const sk = p256.randomPrivateKey();
    const pk = p256.getPublicKey(sk);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = p256.sign({ message, privateKey: sk });
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);

    const ok = p256.verify({ signature: sig, message, publicKey: pk });
    expect(ok).toBe(true);
  });

  it('should sign with recovery and recover matching public key (compressed)', () => {
    const sk = p256.randomPrivateKey();
    const expected = p256.getPublicKey(sk, true);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = p256.sign({ message, privateKey: sk, recovered: true });
    expect(sig.length).toBe(65);

    const recovered = p256.recoverPublicKey({
      signature: sig,
      message,
      compressed: true,
    });
    expect(recovered).toEqual(expected);
  });

  it('should compute ECDH shared secret', () => {
    const aliceSk = p256.randomPrivateKey();
    const alicePk = p256.getPublicKey(aliceSk);
    const bobSk = p256.randomPrivateKey();
    const bobPk = p256.getPublicKey(bobSk);

    const s1 = p256.getSharedSecret({ privateKey: aliceSk, publicKey: bobPk });
    const s2 = p256.getSharedSecret({ privateKey: bobSk, publicKey: alicePk });

    expect(s1).toBeInstanceOf(Uint8Array);
    expect(s1.length).toBe(32);
    expect(s1).toEqual(s2);
  });

  it('should convert to JWK and back (private key)', () => {
    const sk = p256.randomPrivateKey();

    const jwk = p256.toJwkPrivateKey(sk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.d).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = p256.toRawPrivateKey(jwk);
    expect(raw).toEqual(sk);
  });

  it('should convert to JWK and back (public key, uncompressed)', () => {
    const sk = p256.randomPrivateKey();
    const pk = p256.getPublicKey(sk, false);

    const jwk = p256.toJwkPublicKey(pk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = p256.toRawPublicKey(jwk);
    expect(raw).toEqual(pk);
  });
});
