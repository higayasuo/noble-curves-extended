/**
 * A constant array containing the names of supported Edwards curves.
 * Currently, it includes only 'Ed25519'.
 */
export const EDWARDS_CURVE_NAMES = ['Ed25519'] as const;

/**
 * A type representing the name of an Edwards curve.
 * It is a union type of the values in EDWARDS_CURVE_NAMES.
 */
export type EdwardsCurveName = (typeof EDWARDS_CURVE_NAMES)[number];
