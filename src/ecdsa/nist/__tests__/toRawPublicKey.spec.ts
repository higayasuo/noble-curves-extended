import { describe, it, expect } from 'vitest';
import { toRawPublicKey } from '../toRawPublicKey';
import { toJwkPublicKey } from '../toJwkPublickKey';
import { createNistCurve } from '../createNistCurve';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { NistCurveName, RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number) => {
  return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
};

const curves: NistCurveName[] = ['P-256', 'P-384', 'P-521'];

describe('toRawPublicKey', () => {
  it.each(curves)(
    'should convert JWK public key back to raw public key format (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false);

      // Convert public key to JWK
      const jwkPublicKey = toJwkPublicKey({
        curve,
        curveName: name,
        publicKey,
      });

      // Convert JWK back to raw public key
      const rawPublicKey = toRawPublicKey({ curve, jwkPublicKey });

      // The raw public key should match the original public key
      expect(rawPublicKey).toEqual(publicKey);
    },
  );

  it('should throw error for invalid JWK public key', () => {
    const curve = createNistCurve('P-256', randomBytes);
    const invalidJwk = {
      kty: 'EC',
      crv: 'P-256',
      // Missing x and y coordinates
    };

    expect(() =>
      toRawPublicKey({ curve, jwkPublicKey: invalidJwk as any }),
    ).toThrow('Invalid JWK public key: missing x or y coordinates');
  });

  it('should throw error for JWK with invalid base64url coordinates', () => {
    const curve = createNistCurve('P-256', randomBytes);
    const invalidJwk = {
      kty: 'EC',
      crv: 'P-256',
      // Valid base64url strings but invalid for our use case
      x: 'aGVsbG8=', // "hello" in base64url
      y: 'd29ybGQ=', // "world" in base64url
    };

    expect(() =>
      toRawPublicKey({ curve, jwkPublicKey: invalidJwk as any }),
    ).toThrow('Invalid JWK public key: invalid base64url coordinates');
  });
});
