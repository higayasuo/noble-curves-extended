/**
 * Internal module for NIST P521 curves.
 * Do not use for now.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha512 } from '@noble/hashes/sha512';
import { createCurve } from './_shortw_utils';
import { Field } from '@noble/curves/abstract/modular';
import type { CurveFn } from '@noble/curves/abstract/weierstrass';
import type { WeierstrassOpts } from '../abstract/_weierstrass';
import type { RandomBytes } from '../types';

// p = 2n**521n - 1n
const p521_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  ),
  n: BigInt(
    '0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
  ),
  h: BigInt(1),
  a: BigInt(
    '0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc',
  ),
  b: BigInt(
    '0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
  ),
  Gx: BigInt(
    '0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
  ),
  Gy: BigInt(
    '0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
  ),
};

const Fp521 = Field(p521_CURVE.p);

/** NIST P521 (aka secp521r1) curve, ECDSA and ECDH methods. */
export const createP521 = (randomBytes: RandomBytes): CurveFn => {
  return createCurve(
    {
      ...p521_CURVE,
      Fp: Fp521,
      lowS: false,
      allowedPrivateKeyLengths: [130, 131, 132],
    },
    sha512,
    randomBytes,
  );
};
