import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { Jwk } from '../types';
import { compareUint8Arrays, fromB64U } from 'u8a-utils';
import { toRawPublicKey } from './toRawPublicKey';

export type ToRawPrivateKeyParams = {
  curve: CurveFn;
  jwkPrivateKey: Jwk;
};

/**
 * Converts a JWK private key to raw private key format.
 *
 * @param jwkPrivateKey - The JWK private key containing x,y,d coordinates in base64url format.
 * @returns Uint8Array containing the raw private key.
 * @throws Will throw an error if the JWK private key is invalid or missing required properties
 */
export const toRawPrivateKey = ({
  curve,
  jwkPrivateKey,
}: ToRawPrivateKeyParams) => {
  const { d } = jwkPrivateKey;
  if (!d) {
    throw new Error('Invalid JWK private key: missing d coordinate');
  }

  const rawPrivateKey = fromB64U(d);

  if (!curve.utils.isValidPrivateKey(rawPrivateKey)) {
    throw new Error('Invalid JWK private key: invalid private key');
  }

  let rawPublicKey: Uint8Array;
  let rawPublicKeyFromJwk: Uint8Array;

  try {
    rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    rawPublicKeyFromJwk = toRawPublicKey({
      curve,
      jwkPublicKey: jwkPrivateKey,
    });
  } catch (error) {
    throw new Error(`Invalid JWK private key: invalid private key, ${error}`);
  }

  if (!compareUint8Arrays(rawPublicKey, rawPublicKeyFromJwk)) {
    throw new Error('Invalid JWK private key: invalid private key');
  }

  return rawPrivateKey;
};
