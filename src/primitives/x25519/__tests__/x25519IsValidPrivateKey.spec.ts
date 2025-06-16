import { describe, it, expect } from 'vitest';
import { x25519IsValidPrivateKey } from '../x25519IsValidPrivateKey';
import { createX25519 } from '../../../x25519/x25519';
import { randomBytes as cryptoRandomBytes } from 'crypto';
import type { RandomBytes } from '../../../types';
import { decodeHex } from 'u8a-utils';

const randomBytes: RandomBytes = (bytesLength?: number): Uint8Array => {
  return new Uint8Array(cryptoRandomBytes(bytesLength ?? 32));
};

describe('x25519IsValidPrivateKey', () => {
  it('should return true for a valid private key', () => {
    const curve = createX25519(randomBytes);
    const privateKey = curve.utils.randomPrivateKey();
    expect(x25519IsValidPrivateKey(curve, privateKey)).toBe(true);
  });

  it('should return false for an invalid private key (all zeros)', () => {
    const curve = createX25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(32).fill(0);
    expect(x25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should return false for an invalid private key (wrong length)', () => {
    const curve = createX25519(randomBytes);
    const invalidPrivateKey = new Uint8Array(16); // Too short
    expect(x25519IsValidPrivateKey(curve, invalidPrivateKey)).toBe(false);
  });

  it('should validate test vectors from RFC 7748 §5', () => {
    const curve = createX25519(randomBytes);
    const privateKey = decodeHex(
      'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    );
    expect(x25519IsValidPrivateKey(curve, privateKey)).toBe(true);
  });
});
