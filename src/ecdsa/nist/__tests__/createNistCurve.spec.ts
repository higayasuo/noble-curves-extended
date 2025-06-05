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

  it.each(curves)(
    'should convert public and private keys to JWKs (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwkPub = curve.toJwkPublicKey(publicKey);
      const jwkPubDirect = toJwkPublicKey({
        curve,
        curveName: name,
        publicKey,
      });
      expect(jwkPub).toEqual(jwkPubDirect);
      const jwkPriv = curve.toJwkPrivateKey(privateKey);
      const jwkPrivDirect = toJwkPrivateKey({
        curve,
        curveName: name,
        privateKey,
      });
      expect(jwkPriv).toEqual(jwkPrivDirect);
    },
  );

  it('should throw for unsupported curve name', () => {
    // @ts-expect-error
    expect(() => createNistCurve('P-999', randomBytes)).toThrow();
  });
});
