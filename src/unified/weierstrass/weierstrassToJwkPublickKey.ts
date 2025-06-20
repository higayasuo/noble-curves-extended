import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { JwkPublicKey } from '../types';
import { encodeBase64Url } from 'u8a-utils';

export const toJwkPublicKey = (
  curve: CurveFn,
  crv: string,
  publicKey: Uint8Array,
): JwkPublicKey => {
  const point = curve.ProjectivePoint.fromHex(publicKey);
  const uncompressed = point.toRawBytes(false);
  const keyLength = (uncompressed.length - 1) / 2;
  const x = uncompressed.slice(1, 1 + keyLength);
  const y = uncompressed.slice(1 + keyLength);

  return {
    kty: 'EC',
    crv,
    x: encodeBase64Url(x),
    y: encodeBase64Url(y),
  };
};
