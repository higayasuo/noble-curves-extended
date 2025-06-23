import { CurveFn, SignatureType } from '@noble/curves/abstract/weierstrass';

/**
 * Converts a raw signature into a SignatureType using the specified Weierstrass curve.
 *
 * @param {CurveFn} curve - The curve function used for signature conversion.
 * @param {Uint8Array} rawSignature - The raw signature as a Uint8Array.
 * @returns {SignatureType} The converted signature as a SignatureType.
 * @throws {Error} Throws an error if the raw signature length is invalid.
 */
export const fromRawSignature = (
  curve: CurveFn,
  rawSignature: Uint8Array,
): SignatureType => {
  if (rawSignature.length == curve.CURVE.nByteLength * 2) {
    return curve.Signature.fromCompact(rawSignature);
  } else if (rawSignature.length == curve.CURVE.nByteLength * 2 + 1) {
    const compact = rawSignature.slice(0, -1);
    const signature = curve.Signature.fromCompact(compact);
    signature.addRecoveryBit(rawSignature[rawSignature.length - 1]);

    return signature;
  }

  throw new Error('Invalid raw signature');
};
