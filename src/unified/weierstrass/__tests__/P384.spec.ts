import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { P384 } from '../P384';

const p384 = new P384(randomBytes);

describe('P384', () => {
  it('should construct with correct identifiers', () => {
    expect(p384.curveName).toBe('P-384');
    expect(p384.signatureAlgorithmName).toBe('ES384');
    expect(p384.keyByteLength).toBe(48);
    expect(typeof p384.getCurve).toBe('function');
  });

  it('should generate a valid random private key', () => {
    const sk = p384.randomPrivateKey();
    expect(sk).toBeInstanceOf(Uint8Array);
    expect(sk.length).toBe(48);
  });

  it('should derive compressed public key from private key', () => {
    const sk = p384.randomPrivateKey();
    const pk = p384.getPublicKey(sk);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(49);
    expect([0x02, 0x03]).toContain(pk[0]);
  });

  it('should derive uncompressed public key from private key', () => {
    const sk = p384.randomPrivateKey();
    const pk = p384.getPublicKey(sk, false);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(97);
    expect(pk[0]).toBe(0x04);
  });

  it('should sign and verify message', () => {
    const sk = p384.randomPrivateKey();
    const pk = p384.getPublicKey(sk);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = p384.sign({ message, privateKey: sk });
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(96);

    const ok = p384.verify({ signature: sig, message, publicKey: pk });
    expect(ok).toBe(true);
  });

  it('should sign with recovery and recover matching public key (compressed)', () => {
    const sk = p384.randomPrivateKey();
    const expected = p384.getPublicKey(sk, true);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = p384.sign({ message, privateKey: sk, recovered: true });
    expect(sig.length).toBe(97);

    const recovered = p384.recoverPublicKey({
      signature: sig,
      message,
      compressed: true,
    });
    expect(recovered).toEqual(expected);
  });

  it('should compute ECDH shared secret', () => {
    const aliceSk = p384.randomPrivateKey();
    const alicePk = p384.getPublicKey(aliceSk);
    const bobSk = p384.randomPrivateKey();
    const bobPk = p384.getPublicKey(bobSk);

    const s1 = p384.getSharedSecret({ privateKey: aliceSk, publicKey: bobPk });
    const s2 = p384.getSharedSecret({ privateKey: bobSk, publicKey: alicePk });

    expect(s1).toBeInstanceOf(Uint8Array);
    expect(s1.length).toBe(48);
    expect(s1).toEqual(s2);
  });

  it('should convert to JWK and back (private key)', () => {
    const sk = p384.randomPrivateKey();

    const jwk = p384.toJwkPrivateKey(sk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.d).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = p384.toRawPrivateKey(jwk);
    expect(raw).toEqual(sk);
  });

  it('should convert to JWK and back (public key, uncompressed)', () => {
    const sk = p384.randomPrivateKey();
    const pk = p384.getPublicKey(sk, false);

    const jwk = p384.toJwkPublicKey(pk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = p384.toRawPublicKey(jwk);
    expect(raw).toEqual(pk);
  });
});
