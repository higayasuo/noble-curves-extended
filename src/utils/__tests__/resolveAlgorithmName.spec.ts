import { describe, it, expect } from 'vitest';
import {
  curveToAlgorithmName,
  resolveAlgorithmName,
} from '../resolveAlgorithmName';

describe('resolveAlgorithmName', () => {
  describe('curveToAlgorithmName', () => {
    it('should convert P-256 to ES256', () => {
      expect(curveToAlgorithmName('P-256')).toBe('ES256');
    });

    it('should convert P-384 to ES384', () => {
      expect(curveToAlgorithmName('P-384')).toBe('ES384');
    });

    it('should convert P-521 to ES512', () => {
      expect(curveToAlgorithmName('P-521')).toBe('ES512');
    });

    it('should convert secp256k1 to ES256K', () => {
      expect(curveToAlgorithmName('secp256k1')).toBe('ES256K');
    });

    it('should convert Ed25519 to EdDSA', () => {
      expect(curveToAlgorithmName('Ed25519')).toBe('EdDSA');
    });

    it('should convert X25519 to ES256K', () => {
      expect(curveToAlgorithmName('X25519')).toBe('ES256K');
    });

    it('should return undefined for unknown curve', () => {
      expect(curveToAlgorithmName('UNKNOWN')).toBeUndefined();
    });

    it('should return undefined for empty string', () => {
      expect(curveToAlgorithmName('')).toBeUndefined();
    });
  });

  describe('resolveAlgorithmName', () => {
    it('should return algorithmName when only algorithmName is provided', () => {
      expect(resolveAlgorithmName({ algorithmName: 'ES256' })).toBe('ES256');
    });

    it('should return algorithmName for ES384', () => {
      expect(resolveAlgorithmName({ algorithmName: 'ES384' })).toBe('ES384');
    });

    it('should return algorithmName for ES512', () => {
      expect(resolveAlgorithmName({ algorithmName: 'ES512' })).toBe('ES512');
    });

    it('should return algorithmName for ES256K', () => {
      expect(resolveAlgorithmName({ algorithmName: 'ES256K' })).toBe('ES256K');
    });

    it('should return algorithmName for EdDSA', () => {
      expect(resolveAlgorithmName({ algorithmName: 'EdDSA' })).toBe('EdDSA');
    });

    it('should resolve algorithm name from P-256', () => {
      expect(resolveAlgorithmName({ curveName: 'P-256' })).toBe('ES256');
    });

    it('should resolve algorithm name from P-384', () => {
      expect(resolveAlgorithmName({ curveName: 'P-384' })).toBe('ES384');
    });

    it('should resolve algorithm name from P-521', () => {
      expect(resolveAlgorithmName({ curveName: 'P-521' })).toBe('ES512');
    });

    it('should resolve algorithm name from secp256k1', () => {
      expect(resolveAlgorithmName({ curveName: 'secp256k1' })).toBe('ES256K');
    });

    it('should resolve algorithm name from Ed25519', () => {
      expect(resolveAlgorithmName({ curveName: 'Ed25519' })).toBe('EdDSA');
    });

    it('should resolve algorithm name from X25519', () => {
      expect(resolveAlgorithmName({ curveName: 'X25519' })).toBe('ES256K');
    });

    it('should throw error for unsupported curve', () => {
      expect(() => resolveAlgorithmName({ curveName: 'UNKNOWN' })).toThrow(
        "Missing algorithm name: could not resolve algorithm name from curve name 'UNKNOWN'",
      );
    });

    it('should return algorithmName when both match (ES256 and P-256)', () => {
      expect(
        resolveAlgorithmName({ algorithmName: 'ES256', curveName: 'P-256' }),
      ).toBe('ES256');
    });

    it('should return algorithmName when both match (ES384 and P-384)', () => {
      expect(
        resolveAlgorithmName({ algorithmName: 'ES384', curveName: 'P-384' }),
      ).toBe('ES384');
    });

    it('should return algorithmName when both match (ES512 and P-521)', () => {
      expect(
        resolveAlgorithmName({ algorithmName: 'ES512', curveName: 'P-521' }),
      ).toBe('ES512');
    });

    it('should return algorithmName when both match (ES256K and secp256k1)', () => {
      expect(
        resolveAlgorithmName({
          algorithmName: 'ES256K',
          curveName: 'secp256k1',
        }),
      ).toBe('ES256K');
    });

    it('should return algorithmName when both match (EdDSA and Ed25519)', () => {
      expect(
        resolveAlgorithmName({
          algorithmName: 'EdDSA',
          curveName: 'Ed25519',
        }),
      ).toBe('EdDSA');
    });

    it('should return algorithmName when both match (ES256K and X25519)', () => {
      expect(
        resolveAlgorithmName({
          algorithmName: 'ES256K',
          curveName: 'X25519',
        }),
      ).toBe('ES256K');
    });

    it('should throw error when algorithmName and curveName do not match', () => {
      expect(() =>
        resolveAlgorithmName({ algorithmName: 'ES256', curveName: 'P-384' }),
      ).toThrow(
        'Algorithm name mismatch: ES256 does not match algorithm name resolved from curve name: ES384',
      );
    });

    it('should throw error when algorithmName and curveName do not match (different case)', () => {
      expect(() =>
        resolveAlgorithmName({ algorithmName: 'ES384', curveName: 'P-256' }),
      ).toThrow(
        'Algorithm name mismatch: ES384 does not match algorithm name resolved from curve name: ES256',
      );
    });

    it('should throw error when algorithmName and curveName do not match (EdDSA and P-256)', () => {
      expect(() =>
        resolveAlgorithmName({ algorithmName: 'EdDSA', curveName: 'P-256' }),
      ).toThrow(
        'Algorithm name mismatch: EdDSA does not match algorithm name resolved from curve name: ES256',
      );
    });

    it('should throw error when both are undefined', () => {
      expect(() => resolveAlgorithmName({})).toThrow(
        'Either curve name or algorithm name must be provided',
      );
    });

    it('should throw error when both are null', () => {
      expect(() =>
        resolveAlgorithmName({ algorithmName: null, curveName: null } as any),
      ).toThrow('Either curve name or algorithm name must be provided');
    });

    it('should throw error when algorithmName is null and curveName is undefined', () => {
      expect(() =>
        resolveAlgorithmName({
          algorithmName: null,
          curveName: undefined,
        } as any),
      ).toThrow('Either curve name or algorithm name must be provided');
    });

    it('should throw error when algorithmName is undefined and curveName is null', () => {
      expect(() =>
        resolveAlgorithmName({
          algorithmName: undefined,
          curveName: null,
        } as any),
      ).toThrow('Either curve name or algorithm name must be provided');
    });
  });
});
