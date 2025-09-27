import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { P521 } from '../P521';

const p521 = new P521(randomBytes);

describe('P521', () => {
  it('should construct with correct identifiers', () => {
    expect(p521.curveName).toBe('P-521');
    expect(p521.signatureAlgorithmName).toBe('ES512');
    expect(p521.keyByteLength).toBe(66);
    expect(typeof p521.getCurve).toBe('function');
  });

  it('should generate a valid random private key', () => {
    const sk = p521.randomPrivateKey();
    expect(sk).toBeInstanceOf(Uint8Array);
    expect(sk.length).toBe(66);
  });

  it('should derive compressed public key from private key', () => {
    const sk = p521.randomPrivateKey();
    const pk = p521.getPublicKey(sk);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(67);
    expect([0x02, 0x03]).toContain(pk[0]);
  });

  it('should derive uncompressed public key from private key', () => {
    const sk = p521.randomPrivateKey();
    const pk = p521.getPublicKey(sk, false);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(133);
    expect(pk[0]).toBe(0x04);
  });

  it('should sign and verify message', () => {
    const sk = p521.randomPrivateKey();
    const pk = p521.getPublicKey(sk);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = p521.sign({ message, privateKey: sk });
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(132);

    const ok = p521.verify({ signature: sig, message, publicKey: pk });
    expect(ok).toBe(true);
  });

  it('should sign with recovery and recover matching public key (compressed)', () => {
    const sk = p521.randomPrivateKey();
    const expected = p521.getPublicKey(sk, true);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = p521.sign({ message, privateKey: sk, recovered: true });
    expect(sig.length).toBe(133);

    const recovered = p521.recoverPublicKey({
      signature: sig,
      message,
      compressed: true,
    });
    expect(recovered).toEqual(expected);
  });

  it('should compute ECDH shared secret', () => {
    const aliceSk = p521.randomPrivateKey();
    const alicePk = p521.getPublicKey(aliceSk);
    const bobSk = p521.randomPrivateKey();
    const bobPk = p521.getPublicKey(bobSk);

    const s1 = p521.getSharedSecret({ privateKey: aliceSk, publicKey: bobPk });
    const s2 = p521.getSharedSecret({ privateKey: bobSk, publicKey: alicePk });

    expect(s1).toBeInstanceOf(Uint8Array);
    expect(s1.length).toBe(66);
    expect(s1).toEqual(s2);
  });

  it('should convert to JWK and back (private key)', () => {
    const sk = p521.randomPrivateKey();

    const jwk = p521.toJwkPrivateKey(sk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.d).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = p521.toRawPrivateKey(jwk);
    expect(raw).toEqual(sk);
  });

  it('should convert to JWK and back (public key, uncompressed)', () => {
    const sk = p521.randomPrivateKey();
    const pk = p521.getPublicKey(sk, false);

    const jwk = p521.toJwkPublicKey(pk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = p521.toRawPublicKey(jwk);
    expect(raw).toEqual(pk);
  });
});
