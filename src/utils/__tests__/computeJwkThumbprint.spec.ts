import { describe, it, expect } from 'vitest';
import {
  computeEcThumbprintJSON,
  computeOkpThumbprintJSON,
  computeJwkThumbprintJSON,
  computeJwkThumbprint,
} from '../computeJwkThumbprint';
import type { JwkPublicKey } from '@/unified/types';
import { encodeBase64Url } from 'u8a-utils';
import * as jose from 'jose';

describe('computeJwkThumbprint', () => {
  describe('computeEcThumbprintJSON', () => {
    it('should compute thumbprint JSON for valid EC key', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const result = computeEcThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}',
      );
    });

    it('should compute thumbprint JSON for EC key with additional fields (should ignore them)', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        alg: 'ES256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
        kid: 'test-key-id',
        key_ops: ['verify'],
      };

      const result = computeEcThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}',
      );
    });

    it('should throw error when kty is not EC', () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Invalid key type: OKP, expected EC',
      );
    });

    it('should throw error when crv is missing', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for crv',
      );
    });

    it('should throw error when crv is null', () => {
      const jwk = {
        kty: 'EC',
        crv: null,
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      } as unknown as JwkPublicKey;

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for crv',
      );
    });

    it('should throw error when x is missing', () => {
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      } as unknown as JwkPublicKey;

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for x',
      );
    });

    it('should throw error when x is null', () => {
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: null,
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      } as unknown as JwkPublicKey;

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for x',
      );
    });

    it('should throw error when y is missing', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      };

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for y',
      );
    });

    it('should throw error when y is null', () => {
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: null,
      } as unknown as JwkPublicKey;

      expect(() => computeEcThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for y',
      );
    });
  });

  describe('computeOkpThumbprintJSON', () => {
    it('should compute thumbprint JSON for valid OKP key', () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      };

      const result = computeOkpThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
      );
    });

    it('should compute thumbprint JSON for OKP key with additional fields (should ignore them)', () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        kid: 'test-key-id',
        key_ops: ['verify'],
      };

      const result = computeOkpThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
      );
    });

    it('should compute thumbprint JSON for X25519 OKP key', () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'X25519',
        x: '3Gu7VWo1vPpadP3TzV2Z1Tp33jIcG3G2y5X5fzmmmSgk',
      };

      const result = computeOkpThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"X25519","kty":"OKP","x":"3Gu7VWo1vPpadP3TzV2Z1Tp33jIcG3G2y5X5fzmmmSgk"}',
      );
    });

    it('should throw error when kty is not OKP', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      };

      expect(() => computeOkpThumbprintJSON(jwk)).toThrow(
        'Invalid key type: EC, expected OKP',
      );
    });

    it('should throw error when crv is missing', () => {
      const jwk = {
        kty: 'OKP',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      } as unknown as JwkPublicKey;

      expect(() => computeOkpThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for crv',
      );
    });

    it('should throw error when crv is null', () => {
      const jwk = {
        kty: 'OKP',
        crv: null,
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      } as unknown as JwkPublicKey;

      expect(() => computeOkpThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for crv',
      );
    });

    it('should throw error when x is missing', () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
      } as unknown as JwkPublicKey;

      expect(() => computeOkpThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for x',
      );
    });

    it('should throw error when x is null', () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: null,
      } as unknown as JwkPublicKey;

      expect(() => computeOkpThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for x',
      );
    });
  });

  describe('computeJwkThumbprintJSON', () => {
    it('should compute thumbprint JSON for EC key', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const result = computeJwkThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}',
      );
    });

    it('should compute thumbprint JSON for OKP key', () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      };

      const result = computeJwkThumbprintJSON(jwk);

      expect(result).toBe(
        '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
      );
    });

    it('should throw error when kty is not EC or OKP', () => {
      const jwk = {
        kty: 'RSA',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      } as unknown as JwkPublicKey;

      expect(() => computeJwkThumbprintJSON(jwk)).toThrow(
        'Invalid key type: RSA, expected EC or OKP',
      );
    });

    it('should propagate error when EC key is missing required parameters', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      };

      expect(() => computeJwkThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for y',
      );
    });

    it('should propagate error when OKP key is missing required parameters', () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
      } as unknown as JwkPublicKey;

      expect(() => computeJwkThumbprintJSON(jwk)).toThrow(
        'Missing required parameter for x',
      );
    });
  });

  describe('computeJwkThumbprint', () => {
    it('should compute SHA-256 thumbprint for EC key', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const result = computeJwkThumbprint(jwk);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // SHA-256 produces 32 bytes
      // Expected thumbprint value computed from canonical JSON
      expect(encodeBase64Url(result)).toBe(
        'cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s',
      );
    });

    it('should match jose.calculateJwkThumbprint result for EC key', async () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const ourResult = computeJwkThumbprint(jwk);
      const joseResult = await jose.calculateJwkThumbprint(jwk);

      expect(encodeBase64Url(ourResult)).toBe(joseResult);
    });

    it('should compute SHA-256 thumbprint for OKP key', () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      };

      const result = computeJwkThumbprint(jwk);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // SHA-256 produces 32 bytes
      // Expected thumbprint value computed from canonical JSON
      expect(encodeBase64Url(result)).toBe(
        'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
      );
    });

    it('should match jose.calculateJwkThumbprint result for OKP key', async () => {
      const jwk: JwkPublicKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      };

      const ourResult = computeJwkThumbprint(jwk);
      const joseResult = await jose.calculateJwkThumbprint(jwk);

      expect(encodeBase64Url(ourResult)).toBe(joseResult);
    });

    it('should produce consistent thumbprint for same key', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const result1 = computeJwkThumbprint(jwk);
      const result2 = computeJwkThumbprint(jwk);

      expect(result1).toEqual(result2);
    });

    it('should produce different thumbprints for different keys', () => {
      const jwk1: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const jwk2: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-384',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const result1 = computeJwkThumbprint(jwk1);
      const result2 = computeJwkThumbprint(jwk2);

      expect(result1).not.toEqual(result2);
    });

    it('should ignore additional fields when computing thumbprint', () => {
      const jwk1: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      };

      const jwk2: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        alg: 'ES256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
        kid: 'test-key-id',
        key_ops: ['verify'],
      };

      const result1 = computeJwkThumbprint(jwk1);
      const result2 = computeJwkThumbprint(jwk2);

      expect(result1).toEqual(result2);
    });

    it('should match jose.calculateJwkThumbprint when ignoring additional fields', async () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        alg: 'ES256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
        kid: 'test-key-id',
        key_ops: ['verify'],
      };

      const ourResult = computeJwkThumbprint(jwk);
      const joseResult = await jose.calculateJwkThumbprint(jwk);

      expect(encodeBase64Url(ourResult)).toBe(joseResult);
    });

    it('should throw error when kty is not EC or OKP', () => {
      const jwk = {
        kty: 'RSA',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
        y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
      } as unknown as JwkPublicKey;

      expect(() => computeJwkThumbprint(jwk)).toThrow(
        'Invalid key type: RSA, expected EC or OKP',
      );
    });

    it('should propagate error when EC key is missing required parameters', () => {
      const jwk: JwkPublicKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      };

      expect(() => computeJwkThumbprint(jwk)).toThrow(
        'Missing required parameter for y',
      );
    });

    it('should propagate error when OKP key is missing required parameters', () => {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
      } as unknown as JwkPublicKey;

      expect(() => computeJwkThumbprint(jwk)).toThrow(
        'Missing required parameter for x',
      );
    });
  });
});
