import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { Secp256k1 } from '../Secp256k1';

const secp256k1 = new Secp256k1(randomBytes);

describe('Secp256k1', () => {
  it('should construct with correct identifiers', () => {
    expect(secp256k1.curveName).toBe('secp256k1');
    expect(secp256k1.signatureAlgorithmName).toBe('ES256K');
    expect(secp256k1.keyByteLength).toBe(32);
    expect(typeof secp256k1.getCurve).toBe('function');
  });

  it('should generate a valid random private key', () => {
    const sk = secp256k1.randomPrivateKey();
    expect(sk).toBeInstanceOf(Uint8Array);
    expect(sk.length).toBe(32);
  });

  it('should derive compressed public key from private key', () => {
    const sk = secp256k1.randomPrivateKey();
    const pk = secp256k1.getPublicKey(sk);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(33);
    expect([0x02, 0x03]).toContain(pk[0]);
  });

  it('should derive uncompressed public key from private key', () => {
    const sk = secp256k1.randomPrivateKey();
    const pk = secp256k1.getPublicKey(sk, false);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(pk.length).toBe(65);
    expect(pk[0]).toBe(0x04);
  });

  it('should sign and verify message', () => {
    const sk = secp256k1.randomPrivateKey();
    const pk = secp256k1.getPublicKey(sk);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = secp256k1.sign({ message, privateKey: sk });
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);

    const ok = secp256k1.verify({ signature: sig, message, publicKey: pk });
    expect(ok).toBe(true);
  });

  it('should sign with recovery and recover matching public key (compressed)', () => {
    const sk = secp256k1.randomPrivateKey();
    const expected = secp256k1.getPublicKey(sk, true);
    const message = new TextEncoder().encode('Hello, World!');

    const sig = secp256k1.sign({ message, privateKey: sk, recovered: true });
    expect(sig.length).toBe(65);

    const recovered = secp256k1.recoverPublicKey({
      signature: sig,
      message,
      compressed: true,
    });
    expect(recovered).toEqual(expected);
  });

  it('should compute ECDH shared secret', () => {
    const aliceSk = secp256k1.randomPrivateKey();
    const alicePk = secp256k1.getPublicKey(aliceSk);
    const bobSk = secp256k1.randomPrivateKey();
    const bobPk = secp256k1.getPublicKey(bobSk);

    const s1 = secp256k1.getSharedSecret({
      privateKey: aliceSk,
      publicKey: bobPk,
    });
    const s2 = secp256k1.getSharedSecret({
      privateKey: bobSk,
      publicKey: alicePk,
    });

    expect(s1).toBeInstanceOf(Uint8Array);
    expect(s1.length).toBe(32);
    expect(s1).toEqual(s2);
  });

  it('should convert to JWK and back (private key)', () => {
    const sk = secp256k1.randomPrivateKey();

    const jwk = secp256k1.toJwkPrivateKey(sk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.d).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = secp256k1.toRawPrivateKey(jwk);
    expect(raw).toEqual(sk);
  });

  it('should convert to JWK and back (public key, uncompressed)', () => {
    const sk = secp256k1.randomPrivateKey();
    const pk = secp256k1.getPublicKey(sk, false);

    const jwk = secp256k1.toJwkPublicKey(pk);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();

    const raw = secp256k1.toRawPublicKey(jwk);
    expect(raw).toEqual(pk);
  });
});
