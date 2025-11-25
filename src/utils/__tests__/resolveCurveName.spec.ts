import { describe, it, expect } from 'vitest';
import { algorithmToCurveName, resolveCurveName } from '../resolveCurveName';

describe('algorithmToCurveName', () => {
  it('should convert ES256 to P-256', () => {
    expect(algorithmToCurveName('ES256')).toBe('P-256');
  });

  it('should convert ES384 to P-384', () => {
    expect(algorithmToCurveName('ES384')).toBe('P-384');
  });

  it('should convert ES512 to P-521', () => {
    expect(algorithmToCurveName('ES512')).toBe('P-521');
  });

  it('should convert ES256K to secp256k1', () => {
    expect(algorithmToCurveName('ES256K')).toBe('secp256k1');
  });

  it('should throw error for unsupported algorithm', () => {
    expect(() => algorithmToCurveName('EdDSA')).toThrow(
      'Could not resolve curve name from algorithm: EdDSA',
    );
  });

  it('should throw error for unknown algorithm', () => {
    expect(() => algorithmToCurveName('UNKNOWN')).toThrow(
      'Could not resolve curve name from algorithm: UNKNOWN',
    );
  });

  it('should throw error for empty string', () => {
    expect(() => algorithmToCurveName('')).toThrow(
      'Could not resolve curve name from algorithm: ',
    );
  });
});

describe('resolveCurveName', () => {
  describe('when only curveName is provided', () => {
    it('should return curveName when only curveName is provided', () => {
      expect(resolveCurveName({ curveName: 'P-256' })).toBe('P-256');
    });

    it('should return curveName for P-384', () => {
      expect(resolveCurveName({ curveName: 'P-384' })).toBe('P-384');
    });

    it('should return curveName for P-521', () => {
      expect(resolveCurveName({ curveName: 'P-521' })).toBe('P-521');
    });

    it('should return curveName for secp256k1', () => {
      expect(resolveCurveName({ curveName: 'secp256k1' })).toBe('secp256k1');
    });

    it('should return curveName for Ed25519', () => {
      expect(resolveCurveName({ curveName: 'Ed25519' })).toBe('Ed25519');
    });

    it('should return curveName for X25519', () => {
      expect(resolveCurveName({ curveName: 'X25519' })).toBe('X25519');
    });
  });

  describe('when only algorithmName is provided', () => {
    it('should resolve curve name from ES256', () => {
      expect(resolveCurveName({ algorithmName: 'ES256' })).toBe('P-256');
    });

    it('should resolve curve name from ES384', () => {
      expect(resolveCurveName({ algorithmName: 'ES384' })).toBe('P-384');
    });

    it('should resolve curve name from ES512', () => {
      expect(resolveCurveName({ algorithmName: 'ES512' })).toBe('P-521');
    });

    it('should resolve curve name from ES256K', () => {
      expect(resolveCurveName({ algorithmName: 'ES256K' })).toBe('secp256k1');
    });

    it('should throw error for unsupported algorithm', () => {
      expect(() => resolveCurveName({ algorithmName: 'EdDSA' })).toThrow(
        'Could not resolve curve name from algorithm: EdDSA',
      );
    });

    it('should throw error for unknown algorithm', () => {
      expect(() => resolveCurveName({ algorithmName: 'UNKNOWN' })).toThrow(
        'Could not resolve curve name from algorithm: UNKNOWN',
      );
    });
  });

  describe('when both curveName and algorithmName are provided', () => {
    it('should return curveName when both match (ES256 and P-256)', () => {
      expect(
        resolveCurveName({ curveName: 'P-256', algorithmName: 'ES256' }),
      ).toBe('P-256');
    });

    it('should return curveName when both match (ES384 and P-384)', () => {
      expect(
        resolveCurveName({ curveName: 'P-384', algorithmName: 'ES384' }),
      ).toBe('P-384');
    });

    it('should return curveName when both match (ES512 and P-521)', () => {
      expect(
        resolveCurveName({ curveName: 'P-521', algorithmName: 'ES512' }),
      ).toBe('P-521');
    });

    it('should return curveName when both match (ES256K and secp256k1)', () => {
      expect(
        resolveCurveName({
          curveName: 'secp256k1',
          algorithmName: 'ES256K',
        }),
      ).toBe('secp256k1');
    });

    it('should throw error when curveName and algorithmName do not match', () => {
      expect(() =>
        resolveCurveName({ curveName: 'P-256', algorithmName: 'ES384' }),
      ).toThrow('Curve name mismatch: P-256 !== P-384');
    });

    it('should throw error when curveName and algorithmName do not match (different case)', () => {
      expect(() =>
        resolveCurveName({ curveName: 'P-384', algorithmName: 'ES256' }),
      ).toThrow('Curve name mismatch: P-384 !== P-256');
    });

    it('should throw error when algorithmName is unsupported even if curveName is provided', () => {
      expect(() =>
        resolveCurveName({ curveName: 'P-256', algorithmName: 'EdDSA' }),
      ).toThrow('Could not resolve curve name from algorithm: EdDSA');
    });
  });

  describe('when neither curveName nor algorithmName is provided', () => {
    it('should throw error when both are undefined', () => {
      expect(() => resolveCurveName({})).toThrow(
        'Either curveName or algorithmName must be provided',
      );
    });

    it('should throw error when both are empty strings', () => {
      expect(() =>
        resolveCurveName({ curveName: '', algorithmName: '' }),
      ).toThrow('Either curveName or algorithmName must be provided');
    });
  });
});
