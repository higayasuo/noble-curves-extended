/**
 * An array of supported Weierstrass curve names.
 * @type {readonly ['P-256', 'P-384', 'P-521', 'secp256k1']}
 */
export const WEIERSTRASS_CURVE_NAMES = [
  'P-256',
  'P-384',
  'P-521',
  'secp256k1',
] as const;

/**
 * An array of supported Weierstrass signature algorithm names.
 * @type {readonly ['ES256', 'ES384', 'ES512', 'ES256K']}
 */
export const WEIERSTRASS_SIGNATURE_ALGORITHM_NAMES = [
  'ES256',
  'ES384',
  'ES512',
  'ES256K',
] as const;

/**
 * Represents the name of a Weierstrass curve.
 * @typedef {('P-256' | 'P-384' | 'P-521' | 'secp256k1')} WeierstrassCurveName
 */
export type WeierstrassCurveName = (typeof WEIERSTRASS_CURVE_NAMES)[number];

/**
 * Represents the name of a Weierstrass signature algorithm.
 * @typedef {('ES256' | 'ES384' | 'ES512' | 'ES256K')} WeierstrassSignatureAlgorithmName
 */
export type WeierstrassSignatureAlgorithmName =
  (typeof WEIERSTRASS_SIGNATURE_ALGORITHM_NAMES)[number];
