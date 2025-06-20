/**
 * Internal module for NIST P256 curves.
 * Do not use for now.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha256';
import { createCurve } from './_shortw_utils';
import { Field } from '@noble/curves/abstract/modular';
import type { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { WeierstrassOpts } from '../abstract/_weierstrass';
import type { RandomBytes } from '../types';

// p = 2n**224n * (2n**32n-1n) + 2n**192n + 2n**96n - 1n
// a = Fp256.create(BigInt('-3'));
const p256_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  ),
  n: BigInt(
    '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  ),
  h: BigInt(1),
  a: BigInt(
    '0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
  ),
  b: BigInt(
    '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  ),
  Gx: BigInt(
    '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
  ),
  Gy: BigInt(
    '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  ),
};

const Fp256 = Field(p256_CURVE.p);

/** NIST P256 (aka secp256r1, prime256v1) curve, ECDSA and ECDH methods. */
export const createP256 = (randomBytes: RandomBytes): CurveFn => {
  return createCurve(
    { ...p256_CURVE, Fp: Fp256, lowS: false },
    sha256,
    randomBytes,
  );
};
