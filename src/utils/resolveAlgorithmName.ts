/**
 * Converts a curve name to its corresponding algorithm name.
 * Supports P-256, P-384, P-521, secp256k1, Ed25519, and X25519 curves.
 * Returns undefined when the curve name cannot uniquely determine an algorithm name.
 * @typedef {Function} CurveToAlgorithmName
 * @param {string} curveName - The curve name (e.g., 'P-256', 'P-384', 'P-521', 'secp256k1', 'Ed25519', 'X25519')
 * @returns {string|undefined} The corresponding algorithm name, or undefined if the algorithm name cannot be uniquely determined from the curve
 */
export const curveToAlgorithmName = (curveName: string): string | undefined => {
  switch (curveName) {
    case 'P-256':
      return 'ES256';
    case 'P-384':
      return 'ES384';
    case 'P-521':
      return 'ES512';
    case 'secp256k1':
      return 'ES256K';
    case 'Ed25519':
      return 'EdDSA';
    case 'X25519':
      return 'ES256K';
    default:
      return undefined;
  }
};

/**
 * Parameters for resolving algorithm name from JWK fields.
 *
 * @typedef {ResolveAlgorithmNameParams}
 * @property {string} [algorithmName] - The `alg` field from a JWK (may be undefined).
 * @property {string} [curveName] - The `crv` field from a JWK (may be undefined).
 */
export type ResolveAlgorithmNameParams = {
  /** The `alg` field from a JWK (may be undefined). */
  algorithmName?: string;
  /** The `crv` field from a JWK (may be undefined). */
  curveName?: string;
};

/**
 * Resolves the algorithm name from JWK fields.
 * It first checks if the algorithmName is provided. If both algorithmName and curveName are
 * provided, it validates that they are consistent (the algorithm name derived from the curve must
 * match the provided algorithm name). If algorithmName is not provided, it attempts to derive the
 * algorithm name from the curveName using the internal mapping. If neither is available or the
 * curve is not supported, it throws an error.
 * @typedef {Function} ResolveAlgorithmName
 * @param {ResolveAlgorithmNameParams} params - Parameters containing algorithmName and/or curveName
 * @returns {string} The resolved algorithm name
 * @throws {Error} Throws an error if:
 *   - Neither algorithmName nor curveName is provided
 *   - algorithmName and curveName are provided but do not match
 *   - algorithmName is not provided and curveName cannot be resolved to an algorithm name
 */
export const resolveAlgorithmName = ({
  algorithmName,
  curveName,
}: ResolveAlgorithmNameParams): string => {
  if (curveName == null && algorithmName == null) {
    throw new Error('Either curve name or algorithm name must be provided');
  }

  if (algorithmName != null) {
    if (curveName != null) {
      const resolvedAlg = curveToAlgorithmName(curveName);

      if (resolvedAlg != null && resolvedAlg !== algorithmName) {
        throw new Error(
          `Algorithm name mismatch: ${algorithmName} does not match algorithm name resolved from curve name: ${resolvedAlg}`,
        );
      }
    }

    return algorithmName;
  }

  if (curveName == null) {
    throw new Error('Missing algorithm name in JWK');
  }

  const resolvedAlg = curveToAlgorithmName(curveName);

  if (resolvedAlg == null) {
    throw new Error(
      `Missing algorithm name: could not resolve algorithm name from curve name '${curveName}'`,
    );
  }

  return resolvedAlg;
};
