import { RecoveredSignatureType } from '@noble/curves/abstract/weierstrass';

/**
 * Converts a RecoveredSignatureType into a raw signature format.
 *
 * @param {RecoveredSignatureType} signature - The signature to convert.
 * @returns {Uint8Array} The raw signature as a Uint8Array, including the recovery byte.
 */
export const toRawRecoveredSignature = (
  signature: RecoveredSignatureType,
): Uint8Array => {
  if (
    !signature ||
    signature.recovery === undefined ||
    signature.recovery === null
  ) {
    throw new Error('Invalid signature');
  }

  const compact = signature.toCompactRawBytes();
  const rawSignature = new Uint8Array(compact.length + 1);
  rawSignature.set(compact);
  rawSignature[rawSignature.length - 1] = signature.recovery;

  return rawSignature;
};
