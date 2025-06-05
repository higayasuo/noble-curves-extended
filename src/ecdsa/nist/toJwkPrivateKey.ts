import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { Jwk, NistCurveName } from '../../types';
import { toB64U } from 'u8a-utils';
import { toJwkPublicKey } from './toJwkPublickKey';

/**
 * Parameters for converting a private key to JWK format.
 */
export type ToJwkPrivateKeyParams = {
  /** Curve function instance */
  curve: CurveFn;
  /** Name of the elliptic curve */
  curveName: NistCurveName;
  /** Private key */
  privateKey: Uint8Array;
};

/**
 * Converts a private key to JSON Web Key (JWK) format.
 * The function first derives the public key from the private key, then creates a JWK
 * representation that includes both the public key components and the private key.
 *
 * @param params - Parameters containing curve, curve name, and private key
 * @returns JWK representation of the private key
 *
 * @example
 * const jwk = toJwkPrivateKey({
 *   curve: p256,
 *   curveName: 'P-256',
 *   privateKey: '...'
 * });
 */
export const toJwkPrivateKey = ({
  curve,
  curveName,
  privateKey,
}: ToJwkPrivateKeyParams): Jwk => {
  const publicKey = curve.getPublicKey(privateKey);
  const publicJwk = toJwkPublicKey({
    curve,
    curveName,
    publicKey,
  });

  const privateKeyJwk = {
    ...publicJwk,
    d: toB64U(privateKey),
  };

  return privateKeyJwk;
};
