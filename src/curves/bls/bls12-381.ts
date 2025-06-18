import {
  Field,
  getMinHashLength,
  IField,
  mapHashToField,
} from '@noble/curves/abstract/modular';
import { RandomBytes } from '../types';

export const bls12381Fr: IField<bigint> = Field(
  BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'),
);

export const createBls12_381 = (randomBytes: RandomBytes) => {
  const curve = {
    utils: {
      randomPrivateKey: (): Uint8Array => {
        const length = getMinHashLength(bls12381Fr.ORDER);
        return mapHashToField(randomBytes(length), bls12381Fr.ORDER);
      },
    },
  };

  return curve;
};
