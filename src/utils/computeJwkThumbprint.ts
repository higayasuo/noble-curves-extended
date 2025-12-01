import { JwkPublicKey } from '@/unified/types';
import { sha256 } from '@noble/hashes/sha256';

const encoder = new TextEncoder();

/**
 * Computes the thumbprint JSON for an EC (Elliptic Curve) public key.
 * The thumbprint JSON is a canonical JSON representation containing only the required fields: crv, kty, x, and y.
 * @typedef {Function} ComputeEcThumbprintJSON
 * @param {JwkPublicKey} jwk - The JWK public key with kty='EC'
 * @returns {string} The canonical JSON string representation of the EC key thumbprint
 * @throws {Error} Throws an error if:
 *   - kty is not 'EC'
 *   - crv is missing
 *   - x is missing
 *   - y is missing
 */
export const computeEcThumbprintJSON = (jwk: JwkPublicKey): string => {
  const { crv, kty, x, y } = jwk;

  if (kty !== 'EC') {
    throw new Error(`Invalid key type: ${kty}, expected EC`);
  }

  if (crv == null) {
    throw new Error('Missing required parameter for crv');
  }

  if (x == null) {
    throw new Error('Missing required parameter for x');
  }

  if (y == null) {
    throw new Error('Missing required parameter for y');
  }

  return JSON.stringify({ crv, kty, x, y }, ['crv', 'kty', 'x', 'y']);
};

/**
 * Computes the thumbprint JSON for an OKP (Octet Key Pair) public key.
 * The thumbprint JSON is a canonical JSON representation containing only the required fields: crv, kty, and x.
 * @typedef {Function} ComputeOkpThumbprintJSON
 * @param {JwkPublicKey} jwk - The JWK public key with kty='OKP'
 * @returns {string} The canonical JSON string representation of the OKP key thumbprint
 * @throws {Error} Throws an error if:
 *   - kty is not 'OKP'
 *   - crv is missing
 *   - x is missing
 */
export const computeOkpThumbprintJSON = (jwk: JwkPublicKey): string => {
  const { crv, kty, x } = jwk;

  if (kty !== 'OKP') {
    throw new Error(`Invalid key type: ${kty}, expected OKP`);
  }

  if (crv == null) {
    throw new Error('Missing required parameter for crv');
  }

  if (x == null) {
    throw new Error('Missing required parameter for x');
  }

  return JSON.stringify({ crv, kty, x }, ['crv', 'kty', 'x']);
};

/**
 * Computes the thumbprint JSON for a JWK public key.
 * Supports EC (Elliptic Curve) and OKP (Octet Key Pair) key types.
 * @typedef {Function} ComputeJwkThumbprintJSON
 * @param {JwkPublicKey} jwk - The JWK public key with kty='EC' or kty='OKP'
 * @returns {string} The canonical JSON string representation of the key thumbprint
 * @throws {Error} Throws an error if kty is not 'EC' or 'OKP'
 */
export const computeJwkThumbprintJSON = (jwk: JwkPublicKey): string => {
  const { kty } = jwk;

  if (kty === 'EC') {
    return computeEcThumbprintJSON(jwk);
  }

  if (kty === 'OKP') {
    return computeOkpThumbprintJSON(jwk);
  }

  throw new Error(`Invalid key type: ${kty}, expected EC or OKP`);
};

/**
 * Computes the JWK thumbprint as a SHA-256 hash.
 * The thumbprint is computed by first generating the canonical JSON representation of the key,
 * then computing the SHA-256 hash of the UTF-8 encoded JSON string.
 * @typedef {Function} ComputeJwkThumbprint
 * @param {JwkPublicKey} jwk - The JWK public key with kty='EC' or kty='OKP'
 * @returns {Uint8Array} The SHA-256 hash of the thumbprint JSON as a byte array
 * @throws {Error} Throws an error if kty is not 'EC' or 'OKP', or if required parameters are missing
 */
export const computeJwkThumbprint = (jwk: JwkPublicKey): Uint8Array => {
  const thumbprintJSON = computeJwkThumbprintJSON(jwk);
  const thumbprintJSONBytes = encoder.encode(thumbprintJSON);

  return sha256(thumbprintJSONBytes);
};
