import { RandomBytes } from '@/curves/types';
import { Signature, SignatureCurveName } from '../types';
import { createP256 } from '@/curves/weierstrass/p256';
import {
  createEd25519,
  createP384,
  createP521,
  createSecp256k1,
  Edwards,
  Weierstrass,
} from '@/index';

export const createSignature = (
  curveName: SignatureCurveName,
  randomBytes: RandomBytes,
): Signature => {
  switch (curveName) {
    case 'P-256':
      const p256 = createP256(randomBytes);
      return new Weierstrass(p256, randomBytes);
    case 'P-384':
      const p384 = createP384(randomBytes);
      return new Weierstrass(p384, randomBytes);
    case 'P-521':
      const p521 = createP521(randomBytes);
      return new Weierstrass(p521, randomBytes);
    case 'secp256k1':
      const secp256k1 = createSecp256k1(randomBytes);
      return new Weierstrass(secp256k1, randomBytes);
    case 'Ed25519':
      const ed25519 = createEd25519(randomBytes);
      return new Edwards(ed25519, randomBytes);
      d;
  }
};
