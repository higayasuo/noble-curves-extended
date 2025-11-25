import { RandomBytes } from '../../curves/types';

/**
 * Represents the names of supported cryptographic curves.
 * @typedef {('P-256' | 'P-384' | 'P-521' | 'secp256k1' | 'Ed25519' | 'X25519')} CurveName
 */
export type CurveName =
  | 'P-256'
  | 'P-384'
  | 'P-521'
  | 'secp256k1'
  | 'Ed25519'
  | 'X25519';

/**
 * Represents the names of curves used for signature operations.
 * Excludes 'X25519' as it is not used for signatures.
 * @typedef {Exclude<CurveName, 'X25519'>} SignatureCurveName
 */
export type SignatureCurveName = Exclude<CurveName, 'X25519'>;

/**
 * Represents the names of curves used for ECDH operations.
 * Excludes 'Ed25519' as it is not used for ECDH.
 * @typedef {Exclude<CurveName, 'Ed25519'>} EcdhCurveName
 */
export type EcdhCurveName = Exclude<CurveName, 'Ed25519'>;

/**
 * Represents the names of supported signature algorithms.
 * @typedef {('ES256' | 'ES384' | 'ES512' | 'ES256K' | 'EdDSA')} SignatureAlgorithmName
 */
export type SignatureAlgorithmName =
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'ES256K'
  | 'EdDSA';

/**
 * Base JSON Web Key (JWK) structure containing common properties.
 * @typedef {Object} JwkBase
 * @property {string} kty - Key type
 * @property {string} crv - Curve name
 * @property {string} [alg] - Algorithm
 * @property {string} x - X coordinate in base64url format
 * @property {string} [y] - Y coordinate in base64url format
 * @property {string[]} [key_ops] - Key operations
 */
export type JwkBase = {
  kty: string;
  crv?: string;
  alg?: string;
  x: string;
  y?: string;
  key_ops?: string[];
};

/**
 * JSON Web Key (JWK) representation of a public key.
 * Extends JwkBase with an optional key identifier.
 * @typedef {Object} JwkPublicKey
 * @property {string} [kid] - Key identifier
 */
export type JwkPublicKey = JwkBase & {
  kid?: string;
};

/**
 * JSON Web Key (JWK) representation of a private key.
 * Extends JwkBase with a private key component.
 * @typedef {Object} JwkPrivateKey
 * @property {string} d - Private key in base64url format
 */
export type JwkPrivateKey = JwkBase & {
  d: string;
};

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
 * @property {boolean} [recovered] - Optional. Indicates if the signature should be in recovered format.
 */
export type SignParams = {
  privateKey: Uint8Array;
  message: Uint8Array;
  recovered?: boolean;
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
 * Parameters for recovering a public key from a signature.
 * @typedef {Object} RecoverPublicKeyParams
 * @property {Uint8Array} signature - The signature used for recovery as a Uint8Array
 * @property {Uint8Array} message - The message that was signed as a Uint8Array
 * @property {boolean} [compressed] - Whether the recovered public key should be compressed
 */
export type RecoverPublicKeyParams = {
  signature: Uint8Array;
  message: Uint8Array;
  compressed?: boolean;
};

/**
 * Recovers a public key from a signature and message.
 * @typedef {Function} RecoverPublicKey
 * @param {RecoverPublicKeyParams} params - Parameters containing the signature, message, and compression option
 * @returns {Uint8Array} The recovered public key as a Uint8Array
 */
export type RecoverPublicKey = ({
  signature,
  message,
  compressed,
}: RecoverPublicKeyParams) => Uint8Array;

/**
 * Base interface for unified cryptographic operations.
 * @interface UnifiedBase
 * @property {CurveName} curveName - Curve name
 * @property {number} keyByteLength - Key byte length
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
  curveName: CurveName;
  keyByteLength: number;
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
export interface EcdhCurve extends UnifiedBase {
  getSharedSecret: GetSharedSecret;
}

/**
 * Interface for signature operations.
 * Extends UnifiedBase with methods to sign and verify messages.
 * @interface Signature
 * @extends UnifiedBase
 * @property {SignatureAlgorithmName} signatureAlgorithmName - Signature algorithm name
 * @property {Sign} sign - Function to sign a message
 * @property {Verify} verify - Function to verify a signature
 * @property {RecoverPublicKey} recoverPublicKey - Function to recover a public key from a signature and message
 */
export interface SignatureCurve extends UnifiedBase {
  signatureAlgorithmName: SignatureAlgorithmName;
  sign: Sign;
  verify: Verify;
  recoverPublicKey: RecoverPublicKey;
}
