import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { getWeierstrassCurveName } from '@/curves/weierstrass';
import { JwkPublicKey } from '../types';
import { encodeBase64Url } from 'u8a-utils';

export const toJwkPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): JwkPublicKey => {
  try {
    const point = curve.ProjectivePoint.fromHex(publicKey);
    const uncompressed = point.toRawBytes(false);
    const keyLength = (uncompressed.length - 1) / 2;
    const x = uncompressed.slice(1, 1 + keyLength);
    const y = uncompressed.slice(1 + keyLength);

    return {
      kty: 'EC',
      crv: getWeierstrassCurveName(curve),
      x: encodeBase64Url(x),
      y: encodeBase64Url(y),
    };
  } catch (error) {
    console.error(error);
    throw new Error('Failed to convert public key to JWK');
  }
};
