import { describe, it, expect } from 'vitest';
import { isValidPublicKey } from '../isValidPublicKey';
import { createNistCurve } from '../createNistCurve';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { NistCurveName, RandomBytes } from '../../../types';

const randomBytes: RandomBytes = (bytesLength?: number) => {
  return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
};

const curves: NistCurveName[] = ['P-256', 'P-384', 'P-521'];

describe('isValidPublicKey', () => {
  it.each(curves)('should return true for a valid public key (%s)', (name) => {
    const curve = createNistCurve(name, randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    const publicKey = curve.getPublicKey(privateKey, false);
    expect(isValidPublicKey({ curve, publicKey })).toBe(true);
  });

  it.each(curves)(
    'should return false for an obviously invalid public key (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const invalidPublicKey = new Uint8Array([1, 2, 3]);
      expect(isValidPublicKey({ curve, publicKey: invalidPublicKey })).toBe(
        false,
      );
    },
  );

  it.each(curves)(
    'should return false for a mutated valid public key (%s)',
    (name) => {
      const curve = createNistCurve(name, randomBytes);
      const privateKey = curve.utils.randomPrivateKey();
      const publicKey = curve.getPublicKey(privateKey, false);
      // Mutate the last byte
      const mutated = new Uint8Array(publicKey);
      mutated[mutated.length - 1] ^= 0xff;
      expect(isValidPublicKey({ curve, publicKey: mutated })).toBe(false);
    },
  );
});
