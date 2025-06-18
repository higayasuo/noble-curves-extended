import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { Jwk, NistCurveName } from '../types';
import { toB64U } from 'u8a-utils';

/**
 * Parameters for converting a public key to JWK format.
 */
export type ToJwkPublicKeyParams = {
  /** Curve function instance */
  curve: CurveFn;
  /** Name of the elliptic curve */
  curveName: NistCurveName;
  /** Public key */
  publicKey: Uint8Array;
};

/**
 * Converts a public key to JSON Web Key (JWK) format.
 *
 * @param params - Parameters containing curve, curve name, and public key
 * @returns JWK representation of the public key
 *
 * @example
 * const jwk = toJwkPublicKey({
 *   curve: p256,
 *   curveName: 'P-256',
 *   publicKey: '04...'
 * });
 */
export const toJwkPublicKey = ({
  curve,
  curveName,
  publicKey,
}: ToJwkPublicKeyParams): Jwk => {
  const point = curve.ProjectivePoint.fromHex(publicKey);
  const uncompressed = point.toRawBytes(false);
  const keyLength = (uncompressed.length - 1) / 2;
  const x = uncompressed.slice(1, 1 + keyLength);
  const y = uncompressed.slice(1 + keyLength);

  return {
    kty: 'EC',
    crv: curveName,
    x: toB64U(x),
    y: toB64U(y),
  };
};
