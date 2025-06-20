/**
 * SECG secp256k1. See [pdf](https://www.secg.org/sec2-v2.pdf).
 *
 * Belongs to Koblitz curves: it has efficiently-computable GLV endomorphism ψ,
 * check out {@link EndomorphismOpts}. Seems to be rigid (not backdoored).
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha256';
import { createCurve } from './_shortw_utils';
import { Field, mod, pow2 } from '@noble/curves/abstract/modular';
import type { CurveFn } from '@noble/curves/abstract/weierstrass';
import { WeierstrassOpts, EndomorphismOpts } from '../abstract/_weierstrass';
import { RandomBytes } from '../types';

// Seems like generator was produced from some seed:
// `Point.BASE.multiply(Point.Fn.inv(2n, N)).toAffine().x`
// // gives short x 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63n
const secp256k1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  ),
  n: BigInt(
    '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  ),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt(
    '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  ),
  Gy: BigInt(
    '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
  ),
};
const _1n = BigInt(1);
const _2n = BigInt(2);
const divNearest = (a: bigint, b: bigint) => (a + b / _2n) / b;

/**
 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y: bigint): bigint {
  const P = secp256k1_CURVE.p;
  // prettier-ignore
  const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  // prettier-ignore
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = (y * y * y) % P; // x^3, 11
  const b3 = (b2 * b2 * y) % P; // x^7
  const b6 = (pow2(b3, _3n, P) * b3) % P;
  const b9 = (pow2(b6, _3n, P) * b3) % P;
  const b11 = (pow2(b9, _2n, P) * b2) % P;
  const b22 = (pow2(b11, _11n, P) * b11) % P;
  const b44 = (pow2(b22, _22n, P) * b22) % P;
  const b88 = (pow2(b44, _44n, P) * b44) % P;
  const b176 = (pow2(b88, _88n, P) * b88) % P;
  const b220 = (pow2(b176, _44n, P) * b44) % P;
  const b223 = (pow2(b220, _3n, P) * b3) % P;
  const t1 = (pow2(b223, _23n, P) * b22) % P;
  const t2 = (pow2(t1, _6n, P) * b2) % P;
  const root = pow2(t2, _2n, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y)) throw new Error('Cannot find square root');
  return root;
}

const Fpk1 = Field(secp256k1_CURVE.p, undefined, undefined, { sqrt: sqrtMod });

/**
 * secp256k1 curve, ECDSA and ECDH methods.
 *
 * Field: `2n**256n - 2n**32n - 2n**9n - 2n**8n - 2n**7n - 2n**6n - 2n**4n - 1n`
 *
 * @example
 * ```js
 * import { secp256k1 } from '@noble/curves/secp256k1';
 * const priv = secp256k1.utils.randomPrivateKey();
 * const pub = secp256k1.getPublicKey(priv);
 * const msg = new Uint8Array(32).fill(1); // message hash (not message) in ecdsa
 * const sig = secp256k1.sign(msg, priv); // `{prehash: true}` option is available
 * const isValid = secp256k1.verify(sig, msg, pub) === true;
 * ```
 */
export const createSecp256k1 = (randomBytes: RandomBytes): CurveFn => {
  return createCurve(
    {
      ...secp256k1_CURVE,
      Fp: Fpk1,
      lowS: true, // Allow only low-S signatures by default in sign() and verify()
      endo: {
        // Endomorphism, see above
        beta: BigInt(
          '0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee',
        ),
        splitScalar: (k: bigint) => {
          const n = secp256k1_CURVE.n;
          const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
          const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
          const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
          const b2 = a1;
          const POW_2_128 = BigInt('0x100000000000000000000000000000000'); // (2n**128n).toString(16)

          const c1 = divNearest(b2 * k, n);
          const c2 = divNearest(-b1 * k, n);
          let k1 = mod(k - c1 * a1 - c2 * a2, n);
          let k2 = mod(-c1 * b1 - c2 * b2, n);
          const k1neg = k1 > POW_2_128;
          const k2neg = k2 > POW_2_128;
          if (k1neg) k1 = n - k1;
          if (k2neg) k2 = n - k2;
          if (k1 > POW_2_128 || k2 > POW_2_128) {
            throw new Error('splitScalar: Endomorphism failed, k=' + k);
          }
          return { k1neg, k1, k2neg, k2 };
        },
      } satisfies EndomorphismOpts,
    },
    sha256,
    randomBytes,
  );
};
