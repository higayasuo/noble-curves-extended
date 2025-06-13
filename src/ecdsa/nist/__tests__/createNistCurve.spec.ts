import { describe, it, expect } from 'vitest';
import { createNistCurve } from '../createNistCurve';
import { toJwkPublicKey } from '../toJwkPublickKey';
import { toJwkPrivateKey } from '../toJwkPrivateKey';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { NistCurveName, RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number) => {
  return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
};

const curves: NistCurveName[] = ['P-256', 'P-384', 'P-521'];

describe('createNistCurve', () => {
  it.each(curves)(
    'should return a curve instance with correct curveName (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      expect(curve.curveName).toBe(name);
    },
  );

  it.each(curves)('should include randomBytes function (%s)', (name) => {
    const curve = createNistCurve(name, randomBytes);
    expect(curve.randomBytes).toBeDefined();
    expect(typeof curve.randomBytes).toBe('function');

    // Test that randomBytes generates different values
    const bytes1 = curve.randomBytes(32);
    const bytes2 = curve.randomBytes(32);
    expect(bytes1).toHaveLength(32);
    expect(bytes2).toHaveLength(32);
    expect(bytes1).not.toEqual(bytes2);
  });

  it.each(curves)(
    'should convert public and private keys to JWKs (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false);

      // Test public key conversion
      const jwkPub = curve.toJwkPublicKey(publicKey);
      const jwkPubDirect = toJwkPublicKey({
        curve,
        curveName: name,
        publicKey,
      });
      expect(jwkPub).toEqual(jwkPubDirect);

      // Test private key conversion
      const jwkPriv = curve.toJwkPrivateKey(privateKey);
      const jwkPrivDirect = toJwkPrivateKey({
        curve,
        curveName: name,
        privateKey,
      });
      expect(jwkPriv).toEqual(jwkPrivDirect);
    },
  );

  it.each(curves)('should convert JWKs back to raw keys (%s)', (name) => {
    const curve = createNistCurve(name, randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey, false);

    // Convert to JWK
    const jwkPub = curve.toJwkPublicKey(publicKey);
    const jwkPriv = curve.toJwkPrivateKey(privateKey);

    // Convert back to raw using curve instance methods
    const rawPub = curve.toRawPublicKey(jwkPub);
    const rawPriv = curve.toRawPrivateKey(jwkPriv);

    // Verify the round trip
    expect(rawPub).toEqual(publicKey);
    expect(rawPriv).toEqual(privateKey);
  });

  it('should throw for unsupported curve name', () => {
    // @ts-expect-error
    expect(() => createNistCurve('P-999', randomBytes)).toThrow();
  });

  it.each(curves)(
    'should validate public keys using isValidPublicKey (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false);
      // Valid key
      expect(curve.isValidPublicKey(publicKey)).toBe(true);
      // Obviously invalid key
      expect(curve.isValidPublicKey(new Uint8Array([1, 2, 3]))).toBe(false);
      // Mutated valid key
      const mutated = new Uint8Array(publicKey);
      mutated[mutated.length - 1] ^= 0xff;
      expect(curve.isValidPublicKey(mutated)).toBe(false);
    },
  );
});
