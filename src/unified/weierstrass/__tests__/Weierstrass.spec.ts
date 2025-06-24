import { describe, it, expect } from 'vitest';
import { Weierstrass } from '../Weierstrass';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';

const curves = [
  {
    name: 'P-256',
    createCurve: createP256,
    signatureAlgorithmName: 'ES256',
  },
  {
    name: 'P-384',
    createCurve: createP384,
    signatureAlgorithmName: 'ES384',
  },
  {
    name: 'P-521',
    createCurve: createP521,
    signatureAlgorithmName: 'ES512',
  },
  {
    name: 'secp256k1',
    createCurve: createSecp256k1,
    signatureAlgorithmName: 'ES256K',
  },
];

describe('Weierstrass', () => {
  describe('constructor', () => {
    it.each(curves)(
      'should create Weierstrass instance for $name',
      ({ createCurve, name, signatureAlgorithmName }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);

        expect(weierstrass.curve).toBe(curve);
        expect(weierstrass.randomBytes).toBe(randomBytes);
        expect(weierstrass.curveName).toBe(name);
        expect(weierstrass.signatureAlgorithmName).toBe(signatureAlgorithmName);
      },
    );
  });

  describe('getCurve', () => {
    it.each(curves)(
      'should return the underlying curve for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);

        const returnedCurve = weierstrass.getCurve();
        expect(returnedCurve).toBe(curve);
      },
    );
  });

  describe('randomPrivateKey', () => {
    it.each(curves)(
      'should generate valid private key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);

        const privateKey = weierstrass.randomPrivateKey();

        expect(privateKey).toBeInstanceOf(Uint8Array);
        expect(privateKey.length).toBe(curve.CURVE.nByteLength);
      },
    );
  });

  describe('getPublicKey', () => {
    it.each(curves)(
      'should derive public key from private key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();

        const publicKey = weierstrass.getPublicKey(privateKey);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(curve.CURVE.nByteLength + 1); // compressed format
        expect([0x02, 0x03]).toContain(publicKey[0]); // compressed point prefix
      },
    );

    it.each(curves)(
      'should derive uncompressed public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();

        const publicKey = weierstrass.getPublicKey(privateKey, false);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(2 * curve.CURVE.nByteLength + 1); // uncompressed format
        expect(publicKey[0]).toBe(0x04); // uncompressed point prefix
      },
    );
  });

  describe('sign', () => {
    it.each(curves)('should sign message for $name', ({ createCurve }) => {
      const curve = createCurve(randomBytes);
      const weierstrass = new Weierstrass(curve, randomBytes);
      const privateKey = weierstrass.randomPrivateKey();
      const message = new TextEncoder().encode('Hello, World!');

      const signature = weierstrass.sign({ message, privateKey });

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(2 * curve.CURVE.nByteLength); // r and s components
    });

    it.each(curves)(
      'should sign message with recovered signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const message = new TextEncoder().encode('Hello, World!');

        const signature = weierstrass.sign({
          message,
          privateKey,
          recovered: true,
        });

        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(2 * curve.CURVE.nByteLength + 1); // r, s, and recovery components
      },
    );
  });

  describe('verify', () => {
    it.each(curves)(
      'should verify valid signature for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const publicKey = weierstrass.getPublicKey(privateKey);
        const message = new TextEncoder().encode('Hello, World!');

        const signature = weierstrass.sign({ message, privateKey });
        const isValid = weierstrass.verify({ signature, message, publicKey });

        expect(isValid).toBe(true);
      },
    );
  });

  describe('recoverPublicKey', () => {
    it.each(curves)(
      'should recover compressed public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const expectedPublicKey = weierstrass.getPublicKey(privateKey, true); // compressed
        const message = new TextEncoder().encode('Hello, World!');

        const signature = weierstrass.sign({
          message,
          privateKey,
          recovered: true,
        });
        const recoveredPublicKey = weierstrass.recoverPublicKey({
          signature,
          message,
          compressed: true,
        });

        expect(recoveredPublicKey).toBeInstanceOf(Uint8Array);
        expect(recoveredPublicKey.length).toBe(curve.CURVE.nByteLength + 1); // compressed format
        expect(recoveredPublicKey).toEqual(expectedPublicKey);
      },
    );

    it.each(curves)(
      'should recover uncompressed public key for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const expectedPublicKey = weierstrass.getPublicKey(privateKey, false); // uncompressed
        const message = new TextEncoder().encode('Hello, World!');

        const signature = weierstrass.sign({
          message,
          privateKey,
          recovered: true,
        });
        const recoveredPublicKey = weierstrass.recoverPublicKey({
          signature,
          message,
          compressed: false,
        });

        expect(recoveredPublicKey).toBeInstanceOf(Uint8Array);
        expect(recoveredPublicKey.length).toBe(2 * curve.CURVE.nByteLength + 1); // uncompressed format
        expect(recoveredPublicKey).toEqual(expectedPublicKey);
      },
    );
  });

  describe('getSharedSecret', () => {
    it.each(curves)(
      'should compute shared secret for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const alicePrivateKey = weierstrass.randomPrivateKey();
        const alicePublicKey = weierstrass.getPublicKey(alicePrivateKey);
        const bobPrivateKey = weierstrass.randomPrivateKey();
        const bobPublicKey = weierstrass.getPublicKey(bobPrivateKey);

        const aliceSharedSecret = weierstrass.getSharedSecret({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey,
        });
        const bobSharedSecret = weierstrass.getSharedSecret({
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey,
        });

        expect(aliceSharedSecret).toBeInstanceOf(Uint8Array);
        expect(aliceSharedSecret.length).toBe(curve.CURVE.nByteLength);
        expect(aliceSharedSecret).toEqual(bobSharedSecret);
      },
    );
  });

  describe('toJwkPrivateKey', () => {
    it.each(curves)(
      'should convert private key to JWK format for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();

        const jwkPrivateKey = weierstrass.toJwkPrivateKey(privateKey);

        expect(jwkPrivateKey.kty).toBe('EC');
        expect(jwkPrivateKey.crv).toBeDefined();
        expect(jwkPrivateKey.d).toBeDefined();
        expect(jwkPrivateKey.x).toBeDefined();
        expect(jwkPrivateKey.y).toBeDefined();
      },
    );
  });

  describe('toJwkPublicKey', () => {
    it.each(curves)(
      'should convert public key to JWK format for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const publicKey = weierstrass.getPublicKey(privateKey);

        const jwkPublicKey = weierstrass.toJwkPublicKey(publicKey);

        expect(jwkPublicKey.kty).toBe('EC');
        expect(jwkPublicKey.crv).toBeDefined();
        expect(jwkPublicKey.x).toBeDefined();
        expect(jwkPublicKey.y).toBeDefined();
      },
    );
  });

  describe('toRawPrivateKey', () => {
    it.each(curves)(
      'should convert JWK private key to raw format for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const jwkPrivateKey = weierstrass.toJwkPrivateKey(privateKey);

        const rawPrivateKey = weierstrass.toRawPrivateKey(jwkPrivateKey);

        expect(rawPrivateKey).toBeInstanceOf(Uint8Array);
        expect(rawPrivateKey.length).toBe(curve.CURVE.nByteLength);
        expect(rawPrivateKey).toEqual(privateKey);
      },
    );
  });

  describe('toRawPublicKey', () => {
    it.each(curves)(
      'should convert JWK public key to raw format for $name',
      ({ createCurve }) => {
        const curve = createCurve(randomBytes);
        const weierstrass = new Weierstrass(curve, randomBytes);
        const privateKey = weierstrass.randomPrivateKey();
        const publicKey = weierstrass.getPublicKey(privateKey);
        const jwkPublicKey = weierstrass.toJwkPublicKey(publicKey);

        const rawPublicKey = weierstrass.toRawPublicKey(jwkPublicKey);

        expect(rawPublicKey).toBeInstanceOf(Uint8Array);
        expect(rawPublicKey.length).toBe(curve.CURVE.nByteLength + 1); // compressed format
        expect(rawPublicKey).toEqual(publicKey);
      },
    );
  });
});
