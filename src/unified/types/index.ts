import { RandomBytes } from '../../curves/types';

/**
 * JSON Web Key (JWK) representation of a public key.
 * @typedef {Object} JwkPublicKey
 * @property {string} kty - Key type
 * @property {string} crv - Curve name
 * @property {string} [alg] - Algorithm
 * @property {string} x - X coordinate in base64url format
 * @property {string} [y] - Y coordinate in base64url format
 */
export type JwkPublicKey = {
  kty: string;
  crv: string;
  alg?: string;
  x: string;
  y?: string;
};

/**
 * JSON Web Key (JWK) representation of a private key.
 * Extends JwkPublicKey with a private key component.
 * @typedef {Object} JwkPrivateKey
 * @property {string} d - Private key in base64url format
 */
export type JwkPrivateKey = {
  d: string;
} & JwkPublicKey;

/**
 * Converts a private key to a JWK object.
 * @typedef {Function} ToJwkPrivateKey
 * @param {Uint8Array} privateKey - The private key as a Uint8Array
 * @returns {JwkPrivateKey} JWK representation of the private key
 */
export type ToJwkPrivateKey = (privateKey: Uint8Array) => JwkPrivateKey;

/**
 * Converts a public key to a JWK object.
 * @typedef {Function} ToJwkPublicKey
 * @param {Uint8Array} publicKey - The public key as a Uint8Array
 * @returns {JwkPublicKey} JWK representation of the public key
 */
export type ToJwkPublicKey = (publicKey: Uint8Array) => JwkPublicKey;

/**
 * Converts a JWK private key to raw private key format.
 * @typedef {Function} ToRawPrivateKey
 * @param {JwkPrivateKey} privateKey - The JWK private key containing x,y,d coordinates in base64url format
 * @returns {Uint8Array} Uint8Array containing the raw private key
 */
export type ToRawPrivateKey = (privateKey: JwkPrivateKey) => Uint8Array;

/**
 * Converts a JWK public key to raw uncompressed public key format.
 * The resulting format is: 0x04 || x || y where x and y are coordinates.
 * @typedef {Function} ToRawPublicKey
 * @param {JwkPublicKey} publicKey - The JWK public key containing x and y coordinates in base64url format
 * @returns {Uint8Array} Uint8Array containing the raw uncompressed public key
 */
export type ToRawPublicKey = (publicKey: JwkPublicKey) => Uint8Array;

/**
 * Generates a random private key.
 * @typedef {Function} RandomPrivateKey
 * @returns {Uint8Array} A random private key as a Uint8Array
 */
export type RandomPrivateKey = () => Uint8Array;

/**
 * Retrieves the public key from a private key.
 * @typedef {Function} GetPublicKey
 * @param {Uint8Array} privateKey - The private key as a Uint8Array
 * @param {boolean} [compressed] - Whether the public key should be compressed
 * @returns {Uint8Array} The public key as a Uint8Array
 */
export type GetPublicKey = (
  privateKey: Uint8Array,
  compressed?: boolean,
) => Uint8Array;

/**
 * Parameters for generating a shared secret.
 * @typedef {Object} GetSharedSecretParams
 * @property {Uint8Array} privateKey - The private key as a Uint8Array
 * @property {Uint8Array} publicKey - The public key as a Uint8Array
 */
export type GetSharedSecretParams = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

/**
 * Generates a shared secret from a private and public key.
 * @typedef {Function} GetSharedSecret
 * @param {GetSharedSecretParams} params - Parameters containing private and public keys
 * @returns {Uint8Array} The shared secret as a Uint8Array
 */
export type GetSharedSecret = ({
  privateKey,
  publicKey,
}: GetSharedSecretParams) => Uint8Array;

/**
 * Parameters for signing a message.
 * @typedef {Object} SignParams
 * @property {Uint8Array} privateKey - The private key as a Uint8Array
 * @property {Uint8Array} message - The message to sign as a Uint8Array
 * @property {boolean} [recoverable] - Whether the signature should be recoverable
 */
export type SignParams = {
  privateKey: Uint8Array;
  message: Uint8Array;
  recoverable?: boolean;
};

/**
 * Signs a message with a private key.
 * @typedef {Function} Sign
 * @param {SignParams} params - Parameters containing the private key and message
 * @returns {Uint8Array} The signature as a Uint8Array
 */
export type Sign = ({ privateKey, message }: SignParams) => Uint8Array;

/**
 * Parameters for verifying a signature.
 * @typedef {Object} VerifyParams
 * @property {Uint8Array} publicKey - The public key as a Uint8Array
 * @property {Uint8Array} message - The message that was signed as a Uint8Array
 * @property {Uint8Array} signature - The signature to verify as a Uint8Array
 */
export type VerifyParams = {
  publicKey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
};

/**
 * Verifies a signature with a public key and message.
 * @typedef {Function} Verify
 * @param {VerifyParams} params - Parameters containing the public key, message, and signature
 * @returns {boolean} Returns true if the signature is valid, otherwise false.
 */
export type Verify = ({
  publicKey,
  message,
  signature,
}: VerifyParams) => boolean;

/**
 * Base interface for unified cryptographic operations.
 * @interface UnifiedBase
 * @property {string} curveName - Curve name
 * @property {string} signatureAlgorithm - Signature algorithm
 * @property {RandomPrivateKey} randomPrivateKey - Function to generate a random private key
 * @property {GetPublicKey} getPublicKey - Function to retrieve the public key from a private key
 * @property {RandomBytes} randomBytes - Function to generate random bytes
 * @property {ToJwkPrivateKey} toJwkPrivateKey - Function to convert a private key to JWK format
 * @property {ToJwkPublicKey} toJwkPublicKey - Function to convert a public key to JWK format
 * @property {ToRawPrivateKey} toRawPrivateKey - Function to convert a JWK private key to raw format
 * @property {ToRawPublicKey} toRawPublicKey - Function to convert a JWK public key to raw format
 * @property {IsValidPublicKey} isValidPublicKey - Function to validate a public key
 * @property {IsValidPrivateKey} isValidPrivateKey - Function to validate a private key
 */
export interface UnifiedBase {
  curveName: string;
  randomPrivateKey: RandomPrivateKey;
  getPublicKey: GetPublicKey;
  randomBytes: RandomBytes;
  toJwkPrivateKey: ToJwkPrivateKey;
  toJwkPublicKey: ToJwkPublicKey;
  toRawPrivateKey: ToRawPrivateKey;
  toRawPublicKey: ToRawPublicKey;
}

/**
 * Interface for Elliptic Curve Diffie-Hellman (ECDH) operations.
 * Extends UnifiedBase with a method to generate a shared secret.
 * @interface Ecdh
 * @extends UnifiedBase
 * @property {GetSharedSecret} getSharedSecret - Function to generate a shared secret
 */
export interface Ecdh extends UnifiedBase {
  getSharedSecret: GetSharedSecret;
}

/**
 * Interface for signature operations.
 * Extends UnifiedBase with methods to sign and verify messages.
 * @interface Signature
 * @extends UnifiedBase
 * @property {Sign} sign - Function to sign a message
 * @property {Verify} verify - Function to verify a signature
 */
export interface Signature extends UnifiedBase {
  sign: Sign;
  verify: Verify;
}
