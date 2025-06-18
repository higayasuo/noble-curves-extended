import { montgomery, type CurveFn } from '@noble/curves/abstract/montgomery';
import {
  ed25519_CURVE,
  ed25519_pow_2_252_3,
  adjustScalarBytes,
} from '../edwards/ed25519';
import { mod, pow2 } from '@noble/curves/abstract/modular';
import { RandomBytes } from '../../types';

const _3n = BigInt(3);

export const createX25519 = (randomBytes: RandomBytes): CurveFn =>
  /* @__PURE__ */ (() => {
    const P = ed25519_CURVE.p;
    return montgomery({
      P,
      type: 'x25519',
      powPminus2: (x: bigint): bigint => {
        // x^(p-2) aka x^(2^255-21)
        const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
        return mod(pow2(pow_p_5_8, _3n, P) * b2, P);
      },
      adjustScalarBytes,
      randomBytes,
    });
  })();
