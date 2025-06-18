/**
 * Utilities for short weierstrass curves, combined with noble-hashes.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { hmac } from '@noble/hashes/hmac';
import { concatBytes } from '@noble/hashes/utils';
import type { CHash } from '@noble/curves/abstract/utils';
import {
  type CurveFn,
  type CurveType,
  weierstrass,
} from '@noble/curves/abstract/weierstrass';
import type { RandomBytes } from '@/types';

/**
 * Creates a HMAC function using the provided hash function.
 * The function generates HMAC for the concatenated messages using the provided key.
 *
 * @param hash - The hash function to use for HMAC generation
 * @returns A function that generates HMAC for the concatenated messages
 */
export const createHmacFn =
  (hash: CHash) =>
  (key: Uint8Array, ...msgs: Uint8Array[]) =>
    hmac(hash, key, concatBytes(...msgs));

/**
 * Type definition for curve configuration, excluding hash-related properties.
 * Matches the API of @noble/hashes but allows creating curves with custom hash functions.
 */
export type CurveDef = Readonly<
  Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'>
>;

/**
 * Creates a curve function with the ability to generate curves using custom hash functions.
 * The function returns a curve function that includes a create method for generating curves with custom hash functions.
 *
 * @param curveDef - The curve definition excluding hash-related properties
 * @param hash - The default hash function to use
 * @param randomBytes - The random bytes function to use
 * @returns A curve function with an additional create method for generating curves with custom hash functions
 */
export function createCurve(
  curveDef: CurveDef,
  hash: CHash,
  randomBytes: RandomBytes,
): CurveFn {
  return weierstrass({
    ...curveDef,
    hash,
    randomBytes,
    hmac: createHmacFn(hash),
  });
}
