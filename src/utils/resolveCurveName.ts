/**
 * Parameters for resolving a curve name.
 * @typedef {Object} ResolveCurveNameParams
 * @property {string} [curveName] - The curve name (e.g., 'P-256', 'secp256k1')
 * @property {string} [algorithmName] - The algorithm name (e.g., 'ES256', 'ES384')
 */
interface ResolveCurveNameParams {
  curveName?: string;
  algorithmName?: string;
}

/**
 * Converts an algorithm name to its corresponding curve name.
 * Supports ES256, ES384, ES512, and ES256K algorithms.
 * Returns undefined when the algorithm cannot uniquely determine a curve name (e.g., EdDSA can map to Ed25519 or Ed448).
 * @typedef {Function} AlgorithmToCurveName
 * @param {string} algorithmName - The algorithm name (e.g., 'ES256', 'ES384', 'ES512', 'ES256K')
 * @returns {string|undefined} The corresponding curve name, or undefined if the curve name cannot be uniquely determined from the algorithm
 */
export const algorithmToCurveName = (
  algorithmName: string,
): string | undefined => {
  switch (algorithmName) {
    case 'ES256':
      return 'P-256';
    case 'ES384':
      return 'P-384';
    case 'ES512':
      return 'P-521';
    case 'ES256K':
      return 'secp256k1';
    default:
      return undefined;
  }
};

/**
 * Resolves a curve name from either a curve name or an algorithm name.
 * If both are provided, validates that they are consistent.
 * If only algorithmName is provided, derives the curve name from it.
 * If only curveName is provided, returns it as-is.
 * @typedef {Function} ResolveCurveName
 * @param {ResolveCurveNameParams} params - Parameters containing curveName and/or algorithmName
 * @returns {string} The resolved curve name
 * @throws {Error} Throws an error if:
 *   - Neither curveName nor algorithmName is provided
 *   - curveName and algorithmName are provided but do not match
 *   - algorithmName is provided but cannot be resolved to a curve name
 */
export const resolveCurveName = ({
  curveName,
  algorithmName,
}: ResolveCurveNameParams): string => {
  if (curveName == null && algorithmName == null) {
    throw new Error('Either curve name or algorithm name must be provided');
  }

  if (curveName != null) {
    if (algorithmName != null) {
      const resolvedCurveName = algorithmToCurveName(algorithmName);

      if (resolvedCurveName != null && resolvedCurveName !== curveName) {
        throw new Error(
          `Curve name mismatch: ${curveName} does not match curve name resolved from algorithm name: ${resolvedCurveName}`,
        );
      }
    }

    return curveName;
  }

  if (algorithmName == null) {
    throw new Error('Missing curve name in JWK');
  }

  const resolvedCurveName = algorithmToCurveName(algorithmName);

  if (resolvedCurveName == null) {
    throw new Error(
      `Missing curve name: could not resolve curve name from algorithm name '${algorithmName}'`,
    );
  }

  return resolvedCurveName;
};
