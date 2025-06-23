import { CurveFn } from '@noble/curves/abstract/edwards';
import { RandomBytes } from '@/curves/types';
import {
  JwkPrivateKey,
  JwkPublicKey,
  RecoverPublicKeyParams,
  Signature,
  SignParams,
  VerifyParams,
} from '@/unified/types';
import { ed25519RandomPrivateKey } from './ed25519RandomPrivateKey';
import { ed25519GetPublicKey } from './ed25519GetPublicKey';
import { ed25519Sign } from './ed25519Sign';
import { ed25519Verify } from './ed25519Verify';
import { ed25519ToJwkPrivateKey } from './ed25519ToJwkPrivateKey';
import { ed25519ToJwkPublicKey } from './ed25519ToJwkPublicKey';
import { ed25519ToRawPrivateKey } from './ed25519ToRawPrivateKey';
import { ed25519ToRawPublicKey } from './ed25519ToRawPublicKey';

/**
 * Ed25519 implementation for digital signatures.
 * This class provides a high-level interface for Ed25519 operations, including
 * key generation, validation, signing, verification, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const ed25519 = new Ed25519(curve, randomBytes);
 * const privateKey = ed25519.randomPrivateKey();
 * const publicKey = ed25519.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = ed25519.sign({ message, privateKey });
 * const isValid = ed25519.verify({ signature, message, publicKey });
 * ```
 */
export class Ed25519 implements Readonly<Signature> {
  /** The underlying curve implementation */
  readonly curve: CurveFn;
  /** Function to generate random bytes */
  readonly randomBytes: RandomBytes;

  /** Curve identifier for Ed25519 */
  curveName = 'Ed25519';

  /**
   * Creates a new Ed25519 instance.
   *
   * @param {CurveFn} curve - The curve implementation to use
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(curve: CurveFn, randomBytes: RandomBytes) {
    this.curve = curve;
    this.randomBytes = randomBytes;
  }

  /**
   * Gets the underlying curve implementation.
   * This method allows access to the raw CurveFn implementation when needed.
   *
   * @returns {T} The underlying curve implementation
   * @template T The type of the curve implementation
   */
  getCurve<T extends CurveFn = CurveFn>(): T {
    return this.curve as T;
  }

  /**
   * Generates a random private key for Ed25519.
   * The generated key is 32 bytes long and follows RFC 8032 specifications.
   *
   * @returns {Uint8Array} A 32-byte random private key
   */
  randomPrivateKey = (): Uint8Array => {
    return ed25519RandomPrivateKey(this.curve);
  };

  /**
   * Derives a public key from a private key.
   *
   * @param {Uint8Array} privateKey - The private key to derive from
   * @returns {Uint8Array} The derived public key
   * @throws {Error} If the private key is invalid
   */
  getPublicKey = (privateKey: Uint8Array): Uint8Array => {
    return ed25519GetPublicKey(this.curve, privateKey);
  };

  /**
   * Signs a message using the Ed25519 curve and a private key.
   *
   * @param {SignParams} params - An object containing the message and private key.
   * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
   * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
   * @returns {Uint8Array} The signature as a Uint8Array.
   */
  sign = ({ message, privateKey }: SignParams): Uint8Array => {
    return ed25519Sign(this.curve, { message, privateKey });
  };

  /**
   * Verifies a signature using the Ed25519 curve and a public key.
   *
   * @param {VerifyParams} params - An object containing the signature, message, and public key.
   * @param {Uint8Array} params.signature - The signature to be verified as a Uint8Array.
   * @param {Uint8Array} params.message - The message that was signed as a Uint8Array.
   * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
   * @returns {boolean} True if the signature is valid, false otherwise.
   */
  verify = ({ signature, message, publicKey }: VerifyParams): boolean => {
    return ed25519Verify(this.curve, { signature, message, publicKey });
  };

  /**
   * Attempts to recover a public key from a signature and message.
   * Note: Public key recovery is not supported for the Ed25519 curve.
   *
   * @param {RecoverPublicKeyParams} _params - An object containing the signature and message.
   * @throws {Error} Always throws an error as public key recovery is not supported.
   */
  recoverPublicKey = (_params: RecoverPublicKeyParams): Uint8Array => {
    throw new Error('Public key recovery is not supported for this curve');
  };

  /**
   * Converts a private key to JWK format.
   *
   * @param {Uint8Array} privateKey - The private key to convert
   * @returns {JwkPrivateKey} The private key in JWK format
   * @throws {Error} If the private key is invalid
   */
  toJwkPrivateKey = (privateKey: Uint8Array): JwkPrivateKey => {
    return ed25519ToJwkPrivateKey(this.curve, privateKey);
  };

  /**
   * Converts a public key to JWK format.
   *
   * @param {Uint8Array} publicKey - The public key to convert
   * @returns {JwkPublicKey} The public key in JWK format
   * @throws {Error} If the public key is invalid
   */
  toJwkPublicKey = (publicKey: Uint8Array): JwkPublicKey => {
    return ed25519ToJwkPublicKey(this.curve, publicKey);
  };

  /**
   * Converts a JWK private key to raw format.
   *
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key to convert
   * @returns {Uint8Array} The private key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPrivateKey = (jwkPrivateKey: JwkPrivateKey): Uint8Array => {
    return ed25519ToRawPrivateKey(this.curve, jwkPrivateKey);
  };

  /**
   * Converts a JWK public key to raw format.
   *
   * @param {JwkPublicKey} jwkPublicKey - The JWK public key to convert
   * @returns {Uint8Array} The public key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPublicKey = (jwkPublicKey: JwkPublicKey): Uint8Array => {
    return ed25519ToRawPublicKey(this.curve, jwkPublicKey);
  };
}
