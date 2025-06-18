import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { Jwk } from '../types';
import { fromB64U } from 'u8a-utils';

export type ToRawPublicKeyParams = {
  curve: CurveFn;
  jwkPublicKey: Jwk;
};

/**
 * Converts a JWK public key to raw uncompressed public key format.
 * The resulting format is: 0x04 || x || y where x and y are coordinates.
 *
 * @param jwkPublicKey - The JWK public key containing x and y coordinates in base64url format
 * @returns Uint8Array containing the raw uncompressed public key
 * @throws Will throw an error if the JWK public key is invalid or missing required properties
 */
export const toRawPublicKey = ({
  curve,
  jwkPublicKey,
}: ToRawPublicKeyParams) => {
  const { x, y } = jwkPublicKey;
  if (!x || !y) {
    throw new Error('Invalid JWK public key: missing x or y coordinates');
  }

  try {
    const xBytes = fromB64U(x);
    const yBytes = fromB64U(y);
    const rawPublicKey = new Uint8Array([0x04, ...xBytes, ...yBytes]);
    curve.ProjectivePoint.fromHex(rawPublicKey);

    return rawPublicKey;
  } catch (error) {
    throw new Error(
      `Invalid JWK public key: invalid base64url coordinates, ${error}`,
    );
  }
};
