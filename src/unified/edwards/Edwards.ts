import { CurveFn } from '@noble/curves/abstract/edwards';
import { RandomBytes } from '@/curves/types';
import {
  JwkPrivateKey,
  JwkPublicKey,
  RecoverPublicKeyParams,
  SignatureCurve,
  SignParams,
  VerifyParams,
  CurveName,
  SignatureAlgorithmName,
} from '@/unified/types';
import { edwardsRandomPrivateKey } from './edwardsRandomPrivateKey';
import { edwardsGetPublicKey } from './edwardsGetPublicKey';
import { edwardsSign } from './edwardsSign';
import { edwardsVerify } from './edwardsVerify';
import { edwardsToJwkPrivateKey } from './edwardsToJwkPrivateKey';
import { edwardsToJwkPublicKey } from './edwardsToJwkPublicKey';
import { edwardsToRawPrivateKey } from './edwardsToRawPrivateKey';
import { edwardsToRawPublicKey } from './edwardsToRawPublicKey';
import { getEdwardsCurveName } from '@/curves/edwards';

/**
 * Edwards implementation for digital signatures.
 * This class provides a high-level interface for Edwards operations, including
 * key generation, validation, signing, verification, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const edwards = new Edwards(curve, randomBytes);
 * const privateKey = edwards.randomPrivateKey();
 * const publicKey = edwards.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = edwards.sign({ message, privateKey });
 * const isValid = edwards.verify({ signature, message, publicKey });
 * ```
 */
export class Edwards implements Readonly<SignatureCurve> {
  /** The underlying curve implementation */
  readonly curve: CurveFn;
  /** Function to generate random bytes */
  readonly randomBytes: RandomBytes;

  /** Curve identifier for Edwards */
  curveName: CurveName;

  /** Signature algorithm for Edwards */
  signatureAlgorithmName: SignatureAlgorithmName;

  /**
   * Creates a new Edwards instance.
   *
   * @param {CurveFn} curve - The curve implementation to use
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(curve: CurveFn, randomBytes: RandomBytes) {
    this.curve = curve;
    this.randomBytes = randomBytes;
    this.curveName = getEdwardsCurveName(curve);
    this.signatureAlgorithmName = 'EdDSA';
  }

  /**
   * Gets the underlying curve implementation.
   * This method allows access to the raw CurveFn implementation when needed.
   *
   * @returns {T} The underlying curve implementation
   * @template T The type of the curve implementation
   */
  getCurve(): CurveFn {
    return this.curve;
  }

  /**
   * Generates a random private key for Edwards.
   * The generated key is the length of the curve's order.
   *
   * @returns {Uint8Array} A random private key
   */
  randomPrivateKey = (): Uint8Array => {
    return edwardsRandomPrivateKey(this.curve);
  };

  /**
   * Derives a public key from a private key.
   *
   * @param {Uint8Array} privateKey - The private key to derive from
   * @param {boolean} [compressed=true] - Indicates if the public key should be compressed.
   * @returns {Uint8Array} The derived public key
   * @throws {Error} If the private key is invalid
   */
  getPublicKey = (privateKey: Uint8Array, compressed = true): Uint8Array => {
    return edwardsGetPublicKey(this.curve, privateKey, compressed);
  };

  /**
   * Signs a message using the Edwards curve and a private key.
   *
   * @param {SignParams} params - An object containing the message and private key.
   * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
   * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
   * @returns {Uint8Array} The signature as a Uint8Array.
   */
  sign = ({
    message,
    privateKey,
    recovered = false,
  }: SignParams): Uint8Array => {
    return edwardsSign(this.curve, { message, privateKey, recovered });
  };

  /**
   * Verifies a signature using the Edwards curve and a public key.
   *
   * @param {VerifyParams} params - An object containing the signature, message, and public key.
   * @param {Uint8Array} params.signature - The signature to be verified as a Uint8Array.
   * @param {Uint8Array} params.message - The message that was signed as a Uint8Array.
   * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
   * @returns {boolean} True if the signature is valid, false otherwise.
   */
  verify = ({ signature, message, publicKey }: VerifyParams): boolean => {
    return edwardsVerify(this.curve, { signature, message, publicKey });
  };

  /**
   * Attempts to recover a public key from a signature and message.
   * Note: Public key recovery is not supported for the Edwards curve.
   *
   * @param {RecoverPublicKeyParams} _params - An object containing the signature and message.
   * @throws {Error} Always throws an error as public key recovery is not supported.
   */
  recoverPublicKey = (_params: RecoverPublicKeyParams): Uint8Array => {
    throw new Error('Public key recovery is not supported');
  };

  /**
   * Converts a private key to JWK format.
   *
   * @param {Uint8Array} privateKey - The private key to convert
   * @returns {JwkPrivateKey} The private key in JWK format
   * @throws {Error} If the private key is invalid
   */
  toJwkPrivateKey = (privateKey: Uint8Array): JwkPrivateKey => {
    return edwardsToJwkPrivateKey(this.curve, privateKey);
  };

  /**
   * Converts a public key to JWK format.
   *
   * @param {Uint8Array} publicKey - The public key to convert
   * @returns {JwkPublicKey} The public key in JWK format
   * @throws {Error} If the public key is invalid
   */
  toJwkPublicKey = (publicKey: Uint8Array): JwkPublicKey => {
    return edwardsToJwkPublicKey(this.curve, publicKey);
  };

  /**
   * Converts a JWK private key to raw format.
   *
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key to convert
   * @returns {Uint8Array} The private key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPrivateKey = (jwkPrivateKey: JwkPrivateKey): Uint8Array => {
    return edwardsToRawPrivateKey(this.curve, jwkPrivateKey);
  };

  /**
   * Converts a JWK public key to raw format.
   *
   * @param {JwkPublicKey} jwkPublicKey - The JWK public key to convert
   * @returns {Uint8Array} The public key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPublicKey = (jwkPublicKey: JwkPublicKey): Uint8Array => {
    return edwardsToRawPublicKey(this.curve, jwkPublicKey);
  };
}
