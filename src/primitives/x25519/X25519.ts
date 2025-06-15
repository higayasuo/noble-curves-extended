import { CurveFn } from '@noble/curves/abstract/montgomery';
import {
  EcdhPrimitive,
  GetSharedSecretParams,
  JwkPrivateKey,
  JwkPublicKey,
  RandomBytes,
} from '../../types';
import { x25519RandomPrivateKey } from './x25519RandomPrivateKey';
import { x25519GetPublicKey } from './x25519GetPublicKey';
import { x25519ToJwkPrivateKey } from './x25519ToJwkPrivateKey';
import { x25519ToJwkPublicKey } from './x25519ToJwkPublicKey';
import { x25519ToRawPrivateKey } from './x25519ToRawPrivateKey';
import { x25519ToRawPublicKey } from './x25519ToRawPublicKey';
import { x25519IsValidPrivateKey } from './x25519IsValidPrivateKey';
import { x25519IsValidPublicKey } from './x25519IsValidPublicKey';
import { x25519GetSharedSecret } from './x25519GetSharedSecret';

export class X25519 implements Readonly<EcdhPrimitive> {
  readonly curve: CurveFn;
  readonly randomBytes: RandomBytes;

  crv = 'X25519';
  alg = 'ECDH-ES';

  constructor(curve: CurveFn, randomBytes: RandomBytes) {
    this.curve = curve;
    this.randomBytes = randomBytes;
  }

  randomPrivateKey(): Uint8Array {
    return x25519RandomPrivateKey(this.curve);
  }

  getPublicKey(privateKey: Uint8Array, compressed = true): Uint8Array {
    return x25519GetPublicKey(this.curve, privateKey, compressed);
  }

  toJwkPrivateKey(privateKey: Uint8Array): JwkPrivateKey {
    return x25519ToJwkPrivateKey(this.curve, privateKey);
  }

  toJwkPublicKey(publicKey: Uint8Array): JwkPublicKey {
    return x25519ToJwkPublicKey(this.curve, publicKey);
  }

  toRawPrivateKey(jwkPrivateKey: JwkPrivateKey): Uint8Array {
    return x25519ToRawPrivateKey(this.curve, jwkPrivateKey);
  }

  toRawPublicKey(jwkPublicKey: JwkPublicKey): Uint8Array {
    return x25519ToRawPublicKey(this.curve, jwkPublicKey);
  }

  isValidPrivateKey(privateKey: Uint8Array): boolean {
    return x25519IsValidPrivateKey(this.curve, privateKey);
  }

  isValidPublicKey(publicKey: Uint8Array): boolean {
    return x25519IsValidPublicKey(this.curve, publicKey);
  }

  getSharedSecret({
    privateKey,
    publicKey,
  }: GetSharedSecretParams): Uint8Array {
    return x25519GetSharedSecret(this.curve, privateKey, publicKey);
  }
}
