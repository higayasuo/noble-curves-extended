import { describe, it, expect } from 'vitest';
import { toRawPrivateKey } from '../toRawPrivateKey';
import { toJwkPrivateKey } from '../toJwkPrivateKey';
import { createNistCurve } from '../createNistCurve';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { NistCurveName, RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number) => {
  return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
};

const curves: NistCurveName[] = ['P-256', 'P-384', 'P-521'];

describe('toRawPrivateKey', () => {
  it.each(curves)(
    'should convert JWK private key back to raw private key format (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const privateKey = curve.utils.randomPrivateKey();

      // Convert private key to JWK
      const jwkPrivateKey = toJwkPrivateKey({
        curve,
        curveName: name,
        privateKey,
      });

      // Convert JWK back to raw private key
      const rawPrivateKey = toRawPrivateKey({ curve, jwkPrivateKey });

      // The raw private key should match the original private key
      expect(rawPrivateKey).toEqual(privateKey);
    },
  );

  it('should throw error for invalid JWK private key (missing d)', () => {
    const curve = createNistCurve('P-256', randomBytes);
    const invalidJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: 'valid-x',
      y: 'valid-y',
      // Missing d coordinate
    };

    expect(() =>
      toRawPrivateKey({ curve, jwkPrivateKey: invalidJwk as any }),
    ).toThrow('Invalid JWK private key: missing d coordinate');
  });

  it('should throw error for invalid JWK private key (invalid d)', () => {
    const curve = createNistCurve('P-256', randomBytes);
    const invalidJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: 'valid-x',
      y: 'valid-y',
      d: 'aGVsbG8=', // "hello" in base64url - not a valid private key
    };

    expect(() =>
      toRawPrivateKey({ curve, jwkPrivateKey: invalidJwk as any }),
    ).toThrow('Invalid JWK private key: invalid private key');
  });

  it('should throw error for JWK with mismatched public key', () => {
    const curve = createNistCurve('P-256', randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const jwkPrivateKey = toJwkPrivateKey({
      curve,
      curveName: 'P-256',
      privateKey,
    });

    // Modify the public key coordinates to create a mismatch
    jwkPrivateKey.x = 'aGVsbG8='; // "hello" in base64url

    expect(() => toRawPrivateKey({ curve, jwkPrivateKey })).toThrow(
      'Invalid JWK private key: invalid private key',
    );
  });
});
