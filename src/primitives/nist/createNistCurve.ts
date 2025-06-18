import { Jwk, NistCurveName, RandomBytes } from '../../types';
import { CurveFnWithCreate } from '../_shortw_utils';
import { isValidPublicKey } from './isValidPublicKey';
import { createP256, createP384, createP521 } from './nist';
import { toJwkPrivateKey } from './toJwkPrivateKey';
import { toJwkPublicKey } from './toJwkPublickKey';
import { toRawPrivateKey } from './toRawPrivateKey';
import { toRawPublicKey } from './toRawPublicKey';

/**
 * Function type for converting a private key to a JWK object.
 * @param privateKey - The private key as a Uint8Array
 * @returns JWK representation of the private key
 */
type ToJwkPrivateKey = (privateKey: Uint8Array) => Jwk;

/**
 * Function type for converting a public key to a JWK object.
 * @param publicKey - The public key as a Uint8Array
 * @returns JWK representation of the public key
 */
type ToJwkPublicKey = (publicKey: Uint8Array) => Jwk;

/**
 * Function type for converting a JWK private key to raw private key format.
 * @param privateKey - The JWK private key containing x,y,d coordinates in base64url format
 * @returns Uint8Array containing the raw private key
 */
type ToRawPrivateKey = (privateKey: Jwk) => Uint8Array;

/**
 * Function type for converting a JWK public key to raw uncompressed public key format.
 * The resulting format is: 0x04 || x || y where x and y are coordinates.
 * @param publicKey - The JWK public key containing x and y coordinates in base64url format
 * @returns Uint8Array containing the raw uncompressed public key
 */
type ToRawPublicKey = (publicKey: Jwk) => Uint8Array;

/**
 * Function type for validating a public key.
 * @param publicKey - The public key as a Uint8Array
 * @returns {boolean} - Returns true if the public key is valid, otherwise false.
 */
type IsValidPublicKey = (publicKey: Uint8Array) => boolean;

/**
 * Extended curve type for NIST curves, including curve name and JWK conversion helpers.
 * @property curveName - The name of the NIST curve ('P-256', 'P-384', or 'P-521')
 * @property toJwkPrivateKey - Converts a private key to a JWK object
 * @property toJwkPublicKey - Converts a public key to a JWK object
 */
export type NistCurve = CurveFnWithCreate & {
  /** Name of the NIST curve */
  curveName: NistCurveName;
  /** Function to generate random bytes for cryptographic operations */
  randomBytes: RandomBytes;
  /** Converts a private key to a JWK object */
  toJwkPrivateKey: ToJwkPrivateKey;
  /** Converts a public key to a JWK object */
  toJwkPublicKey: ToJwkPublicKey;
  /** Converts a JWK private key to raw private key format */
  toRawPrivateKey: ToRawPrivateKey;
  /** Converts a JWK public key to raw uncompressed public key format */
  toRawPublicKey: ToRawPublicKey;
  /** Validates a public key */
  isValidPublicKey: IsValidPublicKey;
};

/**
 * Creates a NIST curve instance based on the specified curve name.
 *
 * @param curveName - Name of the NIST curve to create. Must be one of: 'P-256', 'P-384', 'P-521'.
 * @param randomBytes - Function to generate random bytes for cryptographic operations.
 * @returns NistCurve instance for the specified NIST curve.
 * @throws {Error} If an unsupported curve name is provided.
 */
export const createNistCurve = (
  curveName: NistCurveName,
  randomBytes: RandomBytes,
): NistCurve => {
  const curve = (() => {
    switch (curveName) {
      case 'P-256':
        return createP256(randomBytes);
      case 'P-384':
        return createP384(randomBytes);
      case 'P-521':
        return createP521(randomBytes);
      default:
        throw new Error(`Unsupported NIST curve: ${curveName}`);
    }
  })();

  return {
    ...curve,
    curveName,
    randomBytes,
    toJwkPrivateKey: (privateKey: Uint8Array) =>
      toJwkPrivateKey({ curve, curveName, privateKey }),
    toJwkPublicKey: (publicKey: Uint8Array) =>
      toJwkPublicKey({ curve, curveName, publicKey }),
    toRawPrivateKey: (jwkPrivateKey: Jwk) =>
      toRawPrivateKey({ curve, jwkPrivateKey }),
    toRawPublicKey: (jwkPublicKey: Jwk) =>
      toRawPublicKey({ curve, jwkPublicKey }),
    isValidPublicKey: (publicKey: Uint8Array) =>
      isValidPublicKey({ curve, publicKey }),
  };
};
