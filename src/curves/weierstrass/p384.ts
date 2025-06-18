/**
 * Internal module for NIST P384 curves.
 * Do not use for now.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha384 } from '@noble/hashes/sha2';
import { createCurve } from './_shortw_utils';
import { Field } from '@noble/curves/abstract/modular';
import type { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { WeierstrassOpts } from '../abstract/_weierstrass';
import type { RandomBytes } from '../types';

// p = 2n**384n - 2n**128n - 2n**96n + 2n**32n - 1n
const p384_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
  ),
  n: BigInt(
    '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
  ),
  h: BigInt(1),
  a: BigInt(
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
  ),
  b: BigInt(
    '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
  ),
  Gx: BigInt(
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
  ),
  Gy: BigInt(
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
  ),
};

const Fp384 = Field(p384_CURVE.p);

/** NIST P384 (aka secp384r1) curve, ECDSA and ECDH methods. */
export const createP384 = (randomBytes: RandomBytes): CurveFn => {
  return createCurve(
    { ...p384_CURVE, Fp: Fp384, lowS: false },
    sha384,
    randomBytes,
  );
};
