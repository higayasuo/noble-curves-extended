import { describe, it, expect } from 'vitest';
import { type CurveFn } from '@noble/curves/abstract/edwards';
import { getEdwardsKeyByteLength } from '../getEdwardsKeyByteLength';
import { createEd25519 } from '../ed25519';

// Helper to make a minimal CurveFn-like object for testing
const makeCurve = (opts: { nByteLength?: number; fpBytes: number }): CurveFn => {
  // We only need properties used by getEdwardsKeyByteLength
  const curveLike: Partial<CurveFn> = {
    CURVE: {
      // @ts-expect-error - we only define what's necessary for this test
      nByteLength: opts.nByteLength,
      // @ts-expect-error - we only define what's necessary for this test
      Fp: { BYTES: opts.fpBytes },
    },
  };
  return curveLike as CurveFn;
};

describe('getEdwardsKeyByteLength', () => {
  it('prefers CURVE.nByteLength when available', () => {
    const curve = makeCurve({ nByteLength: 31, fpBytes: 32 });
    const len = getEdwardsKeyByteLength(curve);
    expect(len).toBe(31);
  });

  it('falls back to CURVE.Fp.BYTES when nByteLength is undefined', () => {
    const curve = makeCurve({ fpBytes: 32 });
    const len = getEdwardsKeyByteLength(curve);
    expect(len).toBe(32);
  });

  it('returns 32 for ed25519', () => {
    // deterministic randomBytes not used by getEdwardsKeyByteLength
    const ed25519: CurveFn = createEd25519(() => new Uint8Array(32));
    const len = getEdwardsKeyByteLength(ed25519);
    expect(len).toBe(32);
  });
});
