/**
 * A constant array containing the names of supported Montgomery curves.
 * Currently, it includes only 'X25519'.
 */
export const MONTGOMERY_CURVE_NAMES = ['X25519'] as const;

/**
 * A type representing the name of an Montgomery curve.
 * It is a union type of the values in MONTGOMERY_CURVE_NAMES.
 */
export type MontgomeryCurveName = (typeof MONTGOMERY_CURVE_NAMES)[number];
