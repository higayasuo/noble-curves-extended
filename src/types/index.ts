/**
 * Function type that generates random bytes.
 * @param bytesLength - Optional number of bytes to generate. If not provided, implementation should choose appropriate length.
 * @returns Uint8Array containing the generated random bytes.
 */
export type RandomBytes = (bytesLength?: number) => Uint8Array;

/**
 * Type representing supported NIST curve names.
 * Possible values: 'P-256', 'P-384', 'P-521'
 */
export type NistCurveName = 'P-256' | 'P-384' | 'P-521';

export type JwkPublicKey = {
  kty: string;
  crv: string;
  alg?: string;
  x: string;
  y?: string;
};

export type JwkPrivateKey = {
  d: string;
} & JwkPublicKey;

/**
 * Function type for converting a private key to a JWK object.
 * @param privateKey - The private key as a Uint8Array
 * @returns JWK representation of the private key
 */
export type ToJwkPrivateKey = (privateKey: Uint8Array) => JwkPrivateKey;

/**
 * Function type for converting a public key to a JWK object.
 * @param publicKey - The public key as a Uint8Array
 * @returns JWK representation of the public key
 */
export type ToJwkPublicKey = (publicKey: Uint8Array) => JwkPublicKey;

/**
 * Function type for converting a JWK private key to raw private key format.
 * @param privateKey - The JWK private key containing x,y,d coordinates in base64url format
 * @returns Uint8Array containing the raw private key
 */
export type ToRawPrivateKey = (privateKey: JwkPrivateKey) => Uint8Array;

/**
 * Function type for converting a JWK public key to raw uncompressed public key format.
 * The resulting format is: 0x04 || x || y where x and y are coordinates.
 * @param publicKey - The JWK public key containing x and y coordinates in base64url format
 * @returns Uint8Array containing the raw uncompressed public key
 */
export type ToRawPublicKey = (publicKey: JwkPublicKey) => Uint8Array;

/**
 * Function type for validating a public key.
 * @param publicKey - The public key as a Uint8Array
 * @returns {boolean} - Returns true if the public key is valid, otherwise false.
 */
export type IsValidPublicKey = (publicKey: Uint8Array) => boolean;

/**
 * Function type for validating a private key.
 * @param privateKey - The private key as a Uint8Array
 * @returns {boolean} - Returns true if the private key is valid, otherwise false.
 */
export type IsValidPrivateKey = (privateKey: Uint8Array) => boolean;

export type RandomPrivateKey = () => Uint8Array;

export type GetPublicKey = (
  privateKey: Uint8Array,
  compressed?: boolean,
) => Uint8Array;

export type GetSharedSecretParams = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export type GetSharedSecret = ({
  privateKey,
  publicKey,
}: GetSharedSecretParams) => Uint8Array;

export type SignParams = {
  privateKey: Uint8Array;
  message: Uint8Array;
};

export type Sign = ({ privateKey, message }: SignParams) => Uint8Array;

export type VerifyParams = {
  publicKey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
};

export type Verify = ({
  publicKey,
  message,
  signature,
}: VerifyParams) => boolean;

export interface PrimitiveBase {
  crv: string;

  alg: string;

  randomPrivateKey: RandomPrivateKey;

  getPublicKey: GetPublicKey;

  randomBytes: RandomBytes;

  toJwkPrivateKey: ToJwkPrivateKey;

  toJwkPublicKey: ToJwkPublicKey;

  toRawPrivateKey: ToRawPrivateKey;

  toRawPublicKey: ToRawPublicKey;

  isValidPublicKey: IsValidPublicKey;

  isValidPrivateKey: IsValidPrivateKey;
}

export interface EcdhPrimitive extends PrimitiveBase {
  getSharedSecret: GetSharedSecret;
}

export interface SignaturePrimitive extends PrimitiveBase {
  sign: Sign;
  verify: Verify;
}
