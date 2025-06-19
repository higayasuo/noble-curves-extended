import { describe, it, expect } from 'vitest';
import { toJwkPrivateKey } from '../toJwkPrivateKey';
import { createP256, createP384, createP521 } from '..';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { RandomBytes, NistCurveName } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number) => {
  return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
};

const curves: { name: NistCurveName; create: typeof createP256 }[] = [
  { name: 'P-256', create: createP256 },
  { name: 'P-384', create: createP384 },
  { name: 'P-521', create: createP521 },
];

describe('toJwkPrivateKey', () => {
  it.each(curves)(
    'should convert a valid private key to JWK (%s)',
    ({ name, create }) => {
      const curve = create(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = toJwkPrivateKey({
        curve,
        curveName: name,
        privateKey,
      });
      expect(jwk).toHaveProperty('kty', 'EC');
      expect(jwk).toHaveProperty('crv', name);
      expect(typeof jwk.x).toBe('string');
      expect(typeof jwk.y).toBe('string');
      expect(typeof jwk.d).toBe('string');
      expect(jwk.x.length).toBeGreaterThan(0);
      expect(jwk.y.length).toBeGreaterThan(0);
      expect(jwk.d).toBeDefined();
      expect(jwk.d!.length).toBeGreaterThan(0);
    },
  );

  it.each(curves)(
    'should throw if the private key is invalid (%s)',
    ({ name, create }) => {
      const curve = create(randomBytes);
      const invalidPrivateKey = new Uint8Array([1, 2, 3]);
      expect(() =>
        toJwkPrivateKey({
          curve,
          curveName: name,
          privateKey: invalidPrivateKey,
        }),
      ).toThrow();
    },
  );

  it.each(curves)(
    'should import the generated JWK using Web Crypto API (%s)',
    async ({ name, create }) => {
      const curve = create(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const jwk = toJwkPrivateKey({
        curve,
        curveName: name,
        privateKey,
      });
      const importedKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        {
          name: 'ECDSA',
          namedCurve: name,
        },
        true,
        ['sign'],
      );
      expect(importedKey).toBeDefined();
      expect(importedKey.type).toBe('private');
    },
  );
});
