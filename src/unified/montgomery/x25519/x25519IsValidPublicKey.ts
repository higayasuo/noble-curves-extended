import { CurveFn } from '@noble/curves/abstract/montgomery';
import { compareUint8Arrays, decodeHex } from 'u8a-utils';

// RFC 7748 §6.1 small order points
const SMALL_ORDER_POINTS = [
  // 0 (order 1)
  '0000000000000000000000000000000000000000000000000000000000000000',
  // 1 (order 1)
  '0100000000000000000000000000000000000000000000000000000000000000',
  // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  // p-1 (order 2)
  '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
  // p (order 4)
  '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
  // p+1 (order 1)
  '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee',
].map((hex) => decodeHex(hex));

/**
 * Validates if a given public key is valid for the x25519 curve.
 *
 * @param {CurveFn} curve - The curve function used to validate the public key.
 * @param {Uint8Array} publicKey - The public key to validate.
 * @returns {boolean} True if the public key is valid, false otherwise.
 */
export const x25519IsValidPublicKey = (
  curve: CurveFn,
  publicKey: Uint8Array,
): boolean => {
  if (publicKey.length !== 32) {
    return false;
  }

  // RFC 7748 §6.1
  // Check for small order points
  if (
    SMALL_ORDER_POINTS.some((point) => compareUint8Arrays(publicKey, point))
  ) {
    return false;
  }

  try {
    const dummyPrivate = curve.utils.randomPrivateKey();
    const sharedSecret = curve.getSharedSecret(dummyPrivate, publicKey);
    return sharedSecret.some((byte) => byte !== 0);
  } catch {
    return false;
  }
};
