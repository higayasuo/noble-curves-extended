import { describe, it, expect } from 'vitest';
import { createBls12_381 } from '../bls12-381';

describe('BLS12-381', () => {
  it('should create a valid random private key', () => {
    // Mock randomBytes to return a predictable value
    const mockRandomBytes = (bytesLength?: number): Uint8Array => {
      return new Uint8Array(bytesLength ?? 32).fill(1);
    };

    const curve = createBls12_381(mockRandomBytes);
    const privateKey = curve.utils.randomPrivateKey();

    // Check that the private key is a Uint8Array
    expect(privateKey).toBeInstanceOf(Uint8Array);

    // Check that the private key is not empty
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('should generate different private keys with different random inputs', () => {
    let counter = 0;
    const mockRandomBytes = (bytesLength?: number): Uint8Array => {
      const result = new Uint8Array(bytesLength ?? 32);
      result.fill(counter++);
      return result;
    };

    const curve = createBls12_381(mockRandomBytes);
    const privateKey1 = curve.utils.randomPrivateKey();
    const privateKey2 = curve.utils.randomPrivateKey();

    // Check that the private keys are different
    expect(privateKey1).not.toEqual(privateKey2);
  });
});
