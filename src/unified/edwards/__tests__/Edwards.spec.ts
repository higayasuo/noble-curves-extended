import { describe, it, expect } from 'vitest';
import { Edwards } from '../Edwards';
import { createEd25519 } from '@/curves/edwards/ed25519';
import { randomBytes } from '@noble/hashes/utils';

const message = new TextEncoder().encode('hello');

const setup = () => {
  const curve = createEd25519(randomBytes);
  const ed = new Edwards(curve, randomBytes);
  return { ed, curve };
};

describe('Edwards', () => {
  it('should have correct curveName properties', () => {
    const { ed } = setup();
    expect(ed.curveName).toBe('Ed25519');
  });

  it('should have correct signatureAlgorithmName property', () => {
    const { ed } = setup();
    expect(ed.signatureAlgorithmName).toBe('EdDSA');
  });

  describe('randomPrivateKey', () => {
    it('should generate a valid private key', () => {
      const { ed, curve } = setup();
      const priv = ed.randomPrivateKey();
      expect(priv).toBeInstanceOf(Uint8Array);
      expect(priv.length).toBe(curve.CURVE.nByteLength);
    });
    it('should generate different keys on each call', () => {
      const { ed } = setup();
      const priv1 = ed.randomPrivateKey();
      const priv2 = ed.randomPrivateKey();
      expect(priv1).not.toEqual(priv2);
    });
  });

  describe('getPublicKey', () => {
    it('should derive a public key from a valid private key', () => {
      const { ed, curve } = setup();
      const priv = ed.randomPrivateKey();
      const pub = ed.getPublicKey(priv);
      expect(pub).toBeInstanceOf(Uint8Array);
      expect(pub.length).toBe(curve.CURVE.nByteLength);
    });
    it('should throw for an invalid private key', () => {
      const { ed } = setup();
      const invalidPriv = new Uint8Array(16);
      expect(() => ed.getPublicKey(invalidPriv)).toThrow();
    });
    it('should throw error when compressed is set to false', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      expect(() => ed.getPublicKey(priv, false)).toThrow(
        'Uncompressed public key is not supported',
      );
    });
  });

  describe('sign', () => {
    it('should sign a message with a valid private key', () => {
      const { ed, curve } = setup();
      const priv = ed.randomPrivateKey();
      const sig = ed.sign({ message, privateKey: priv });
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(sig.length).toBe(curve.CURVE.nByteLength * 2);
    });
    it('should throw for an invalid private key', () => {
      const { ed } = setup();
      const invalidPriv = new Uint8Array(16);
      expect(() => ed.sign({ message, privateKey: invalidPriv })).toThrow();
    });
    it('should throw error when recovered is set to true', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      expect(() =>
        ed.sign({ message, privateKey: priv, recovered: true }),
      ).toThrow('Recovered signature is not supported');
    });
  });

  describe('verify', () => {
    it('should verify a valid signature', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      const pub = ed.getPublicKey(priv);
      const sig = ed.sign({ message, privateKey: priv });
      expect(ed.verify({ signature: sig, message, publicKey: pub })).toBe(true);
    });
    it('should return false for an invalid signature', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      const pub = ed.getPublicKey(priv);
      const invalidSig = new Uint8Array(64);
      expect(
        ed.verify({ signature: invalidSig, message, publicKey: pub }),
      ).toBe(false);
    });
  });

  describe('recoverPublicKey', () => {
    it('should throw error as public key recovery is not supported', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      const sig = ed.sign({ message, privateKey: priv });

      expect(() => ed.recoverPublicKey({ message, signature: sig })).toThrow(
        'Public key recovery is not supported',
      );
    });
  });

  describe('toJwkPrivateKey', () => {
    it('should convert a valid private key to JWK', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      const jwk = ed.toJwkPrivateKey(priv);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'Ed25519');
      expect(jwk).toHaveProperty('d');
      expect(jwk).toHaveProperty('x');
    });
    it('should throw for an invalid private key', () => {
      const { ed } = setup();
      const invalidPriv = new Uint8Array(16);
      expect(() => ed.toJwkPrivateKey(invalidPriv)).toThrow();
    });
  });

  describe('toJwkPublicKey', () => {
    it('should convert a valid public key to JWK', () => {
      const { ed } = setup();
      const priv = ed.randomPrivateKey();
      const pub = ed.getPublicKey(priv);
      const jwk = ed.toJwkPublicKey(pub);
      expect(jwk).toHaveProperty('kty', 'OKP');
      expect(jwk).toHaveProperty('crv', 'Ed25519');
      expect(jwk).toHaveProperty('x');
    });
  });

  describe('toRawPrivateKey', () => {
    it('should convert a valid JWK private key to raw', () => {
      const { ed, curve } = setup();
      const priv = ed.randomPrivateKey();
      const jwk = ed.toJwkPrivateKey(priv);
      const raw = ed.toRawPrivateKey(jwk);
      expect(raw).toBeInstanceOf(Uint8Array);
      expect(raw.length).toBe(curve.CURVE.nByteLength);
    });
    it('should throw for an invalid JWK private key', () => {
      const { ed } = setup();
      const invalidJwk = { kty: 'EC', crv: 'Ed25519', d: 'AA', x: 'AA' } as any;
      expect(() => ed.toRawPrivateKey(invalidJwk)).toThrow();
    });
  });

  describe('toRawPublicKey', () => {
    it('should convert a valid JWK public key to raw', () => {
      const { ed, curve } = setup();
      const priv = ed.randomPrivateKey();
      const pub = ed.getPublicKey(priv);
      const jwk = ed.toJwkPublicKey(pub);
      const raw = ed.toRawPublicKey(jwk);
      expect(raw).toBeInstanceOf(Uint8Array);
      expect(raw.length).toBe(curve.CURVE.nByteLength);
    });
    it('should throw for an invalid JWK public key', () => {
      const { ed } = setup();
      const invalidJwk = { kty: 'EC', crv: 'Ed25519', x: 'AA' } as any;
      expect(() => ed.toRawPublicKey(invalidJwk)).toThrow();
    });
  });
});
