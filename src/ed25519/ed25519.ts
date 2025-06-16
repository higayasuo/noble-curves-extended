/**
 * ed25519 Twisted Edwards curve with following addons:
 * - X25519 ECDH
 * - Ristretto cofactor elimination
 * - Elligator hash-to-group / point indistinguishability
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha512 } from '@noble/hashes/sha2';
import { type CurveFn, twistedEdwards } from '@noble/curves/abstract/edwards';
import { type Hex } from '@noble/curves/abstract/utils';
import { type EdwardsOpts } from '../abstract/_edwards';
import { Field, isNegativeLE, mod, pow2 } from '@noble/curves/abstract/modular';
import { isBytes } from '@noble/hashes/utils';
import { RandomBytes } from '../types';
import { ensureUint8Array, isUint8Array } from 'u8a-utils';

// prettier-ignore
const _1n = BigInt(1), _2n = BigInt(2), _5n = BigInt(5), _8n = BigInt(8);

// 2n**255n - 19n
// Removing Fp.create() will still work, and is 10% faster on sign
//     a: Fp.create(BigInt(-1)),
// d is -121665/121666 a.k.a. Fp.neg(121665 * Fp.inv(121666))
// Finite field 2n**255n - 19n
// Subgroup order 2n**252n + 27742317777372353535851937790883648493n;
export const ed25519_CURVE: EdwardsOpts = {
  p: BigInt(
    '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
  ),
  n: BigInt(
    '0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
  ),
  h: _8n,
  a: BigInt(
    '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
  ),
  d: BigInt(
    '0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3',
  ),
  Gx: BigInt(
    '0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a',
  ),
  Gy: BigInt(
    '0x6666666666666666666666666666666666666666666666666666666666666658',
  ),
};

export function ed25519_pow_2_252_3(x: bigint) {
  // prettier-ignore
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ed25519_CURVE.p;
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, _2n, P) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, _1n, P) * x) % P; // x^31
  const b10 = (pow2(b5, _5n, P) * b5) % P;
  const b20 = (pow2(b10, _10n, P) * b10) % P;
  const b40 = (pow2(b20, _20n, P) * b20) % P;
  const b80 = (pow2(b40, _40n, P) * b40) % P;
  const b160 = (pow2(b80, _80n, P) * b80) % P;
  const b240 = (pow2(b160, _80n, P) * b80) % P;
  const b250 = (pow2(b240, _10n, P) * b10) % P;
  const pow_p_5_8 = (pow2(b250, _2n, P) * x) % P;
  // ^ To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}

export function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

// √(-1) aka √(a) aka 2^((p-1)/4)
// Fp.sqrt(Fp.neg(1))
const ED25519_SQRT_M1 = /* @__PURE__ */ BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752',
);
// sqrt(u/v)
function uvRatio(u: bigint, v: bigint): { isValid: boolean; value: bigint } {
  const P = ed25519_CURVE.p;
  const v3 = mod(v * v * v, P); // v³
  const v7 = mod(v3 * v3 * v, P); // v⁷
  // (p+3)/8 and (p-5)/8
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P); // (uv³)(uv⁷)^(p-5)/8
  const vx2 = mod(v * x * x, P); // vx²
  const root1 = x; // First root candidate
  const root2 = mod(x * ED25519_SQRT_M1, P); // Second root candidate
  const useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
  const useRoot2 = vx2 === mod(-u, P); // If vx² = -u, set x <-- x * 2^((p-1)/4)
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P); // There is no valid root, vx² = -u√(-1)
  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2; // We return root2 anyway, for const-time
  if (isNegativeLE(x, P)) x = mod(-x, P);
  return { isValid: useRoot1 || useRoot2, value: x };
}

/** Weird / bogus points, useful for debugging. */
// export const ED25519_TORSION_SUBGROUP: string[] = [
//   '0100000000000000000000000000000000000000000000000000000000000000',
//   'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
//   '0000000000000000000000000000000000000000000000000000000000000080',
//   '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
//   'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
//   '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
//   '0000000000000000000000000000000000000000000000000000000000000000',
//   'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
// ];

const Fp = /* @__PURE__ */ (() => Field(ed25519_CURVE.p, undefined, true))();

const ed25519Defaults = /* @__PURE__ */ (() => ({
  ...ed25519_CURVE,
  Fp,
  hash: sha512,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio,
}))();

/**
 * ed25519 curve with EdDSA signatures.
 * @example
 * import { ed25519 } from '@noble/curves/ed25519';
 * const priv = ed25519.utils.randomPrivateKey();
 * const pub = ed25519.getPublicKey(priv);
 * const msg = new TextEncoder().encode('hello');
 * const sig = ed25519.sign(msg, priv);
 * ed25519.verify(sig, msg, pub); // Default mode: follows ZIP215
 * ed25519.verify(sig, msg, pub, { zip215: false }); // RFC8032 / FIPS 186-5
 */
export const createEd25519 = (randomBytes: RandomBytes): CurveFn => {
  const curve = twistedEdwards({
    ...ed25519Defaults,
    randomBytes,
  });

  const modified: CurveFn = {
    ...curve,
    sign: (message: Hex, privateKey: Hex, options?: { context?: Hex }) => {
      if (isUint8Array(message)) {
        message = ensureUint8Array(message);
      }

      return curve.sign(message, privateKey, options);
    },
    verify: (
      signature: Hex,
      message: Hex,
      publicKey: Hex,
      options?: { context?: Hex; zip215: boolean },
    ) => {
      if (isUint8Array(message)) {
        message = ensureUint8Array(message);
      }

      return curve.verify(signature, message, publicKey, options);
    },
    utils: {
      ...curve.utils,
      randomPrivateKey: () => {
        const edRaw = curve.utils.randomPrivateKey();
        const edHash = sha512(edRaw);
        return adjustScalarBytes(edHash.slice(0, 32));
      },
    },
  };

  return modified;
};
//twistedEdwards({ ...ed25519Defaults, randomBytes });
