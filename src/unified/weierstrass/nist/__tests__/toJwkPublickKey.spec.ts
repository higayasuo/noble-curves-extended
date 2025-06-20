import { describe, it, expect } from 'vitest';
import { toJwkPublicKey } from '../../weierstrassToJwkPublickKey';
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

describe('toJwkPublicKey', () => {
  it.each(curves)(
    'should convert a valid public key to JWK (%s)',
    ({ name, create }) => {
      const curve = create(randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey);
      const jwk = toJwkPublicKey({
        curve,
        curveName: name,
        publicKey,
      });
      expect(jwk).toHaveProperty('kty', 'EC');
      expect(jwk).toHaveProperty('crv', name);
      expect(typeof jwk.x).toBe('string');
      expect(typeof jwk.y).toBe('string');
      expect(jwk.x.length).toBeGreaterThan(0);
      expect(jwk.y.length).toBeGreaterThan(0);
    },
  );

  it.each(curves)(
    'should throw if the public key is invalid (%s)',
    ({ name, create }) => {
      const curve = create(randomBytes);
      const invalidPublicKey = new Uint8Array([1, 2, 3]);
      expect(() =>
        toJwkPublicKey({
          curve,
          curveName: name,
          publicKey: invalidPublicKey,
        }),
      ).toThrow();
    },
  );

  it.each(curves)(
    'should import the generated JWK using Web Crypto API (%s)',
    async ({ name, create }) => {
      const curve = create(randomBytes);
      for (const compressed of [true, false]) {
        const privateKey = curve.utils.randomPrivateKey();
        const publicKey = curve.getPublicKey(privateKey, compressed);
        const jwk = toJwkPublicKey({
          curve,
          curveName: name,
          publicKey,
        });
        const importedKey = await crypto.subtle.importKey(
          'jwk',
          jwk,
          {
            name: 'ECDSA',
            namedCurve: name,
          },
          true,
          ['verify'],
        );
        expect(importedKey).toBeDefined();
        expect(importedKey.type).toBe('public');
      }
    },
  );
});
