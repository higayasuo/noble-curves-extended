import { CurveFn } from '@noble/curves/abstract/weierstrass';
import { RandomBytes } from '@/curves/types';
import {
  JwkPrivateKey,
  JwkPublicKey,
  SignatureCurve,
  SignParams,
  VerifyParams,
  GetSharedSecretParams,
  EcdhCurve,
  RecoverPublicKeyParams,
  CurveName,
  SignatureAlgorithmName,
} from '@/unified/types';
import { weierstrassRandomPrivateKey } from './weierstrassRandomPrivateKey';
import { weierstrassGetPublicKey } from './weierstrassGetPublicKey';
import { weierstrassSign } from './weierstrassSign';
import { weierstrassVerify } from './weierstrassVerify';
import { weierstrassGetSharedSecret } from './weierstrassGetSharedSecret';
import { weierstrassToJwkPrivateKey } from './weierstrassToJwkPrivateKey';
import { weierstrassToJwkPublickKey } from './weierstrassToJwkPublickKey';
import { weierstrassToRawPrivateKey } from './weierstrassToRawPrivateKey';
import { weierstrassToRawPublicKey } from './weierstrassToRawPublicKey';
import { getWeierstrassCurveName } from '@/curves/weierstrass/getWeierstrassCurveName';
import { weierstrassRecoverPublicKey } from './weierstrassRecoverPublicKey';
import { getWeierstrassSignatureAlgorithm } from '@/curves/weierstrass/getWeierstrassSignatureAlgorithm';

/**
 * Weierstrass curve implementation for digital signatures and ECDH.
 * This class provides a high-level interface for Weierstrass curve operations, including
 * key generation, validation, signing, verification, ECDH, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const weierstrass = new Weierstrass(curve, randomBytes);
 * const privateKey = weierstrass.randomPrivateKey();
 * const publicKey = weierstrass.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = weierstrass.sign({ message, privateKey });
 * const isValid = weierstrass.verify({ signature, message, publicKey });
 * const sharedSecret = weierstrass.getSharedSecret({ privateKey, publicKey: otherPublicKey });
 * ```
 */
export class Weierstrass
  implements Readonly<SignatureCurve>, Readonly<EcdhCurve>
{
  /** The underlying curve implementation */
  readonly curve: CurveFn;
  /** Function to generate random bytes */
  readonly randomBytes: RandomBytes;

  /** Curve identifier for Weierstrass curves */
  curveName: CurveName;

  /** Signature algorithm for Weierstrass curves */
  signatureAlgorithmName: SignatureAlgorithmName;

  /**
   * Creates a new Weierstrass instance.
   *
   * @param {CurveFn} curve - The curve implementation to use
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(curve: CurveFn, randomBytes: RandomBytes) {
    this.curve = curve;
    this.randomBytes = randomBytes;
    this.curveName = getWeierstrassCurveName(curve);
    this.signatureAlgorithmName = getWeierstrassSignatureAlgorithm(curve);
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
   * Generates a random private key for Weierstrass curves.
   * The generated key length depends on the specific curve used.
   *
   * @returns {Uint8Array} A random private key
   */
  randomPrivateKey = (): Uint8Array => {
    return weierstrassRandomPrivateKey(this.curve);
  };

  /**
   * Derives a public key from a private key.
   *
   * @param {Uint8Array} privateKey - The private key to derive from
   * @returns {Uint8Array} The derived public key
   * @throws {Error} If the private key is invalid
   */
  getPublicKey = (privateKey: Uint8Array, compressed = true): Uint8Array => {
    return weierstrassGetPublicKey(this.curve, privateKey, compressed);
  };

  /**
   * Signs a message using the Weierstrass curve and a private key.
   *
   * @param {SignParams} params - An object containing the message and private key.
   * @param {Uint8Array} params.message - The message to be signed as a Uint8Array.
   * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
   * @param {boolean} [params.recovered=false] - Indicates if the signature should be in recovered format.
   * @returns {Uint8Array} The signature as a Uint8Array.
   */
  sign = ({
    message,
    privateKey,
    recovered = false,
  }: SignParams): Uint8Array => {
    return weierstrassSign(this.curve, { message, privateKey, recovered });
  };

  /**
   * Verifies a signature using the Weierstrass curve and a public key.
   *
   * @param {VerifyParams} params - An object containing the signature, message, and public key.
   * @param {Uint8Array} params.signature - The signature to be verified as a Uint8Array.
   * @param {Uint8Array} params.message - The message that was signed as a Uint8Array.
   * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
   * @returns {boolean} True if the signature is valid, false otherwise.
   */
  verify = ({ signature, message, publicKey }: VerifyParams): boolean => {
    return weierstrassVerify(this.curve, { signature, message, publicKey });
  };

  /**
   * Recovers the public key from a given signature and message using the Weierstrass curve.
   *
   * @param {RecoverPublicKeyParams} params - An object containing the signature and message.
   * @param {Uint8Array} params.signature - The signature from which to recover the public key.
   * @param {Uint8Array} params.message - The message that was signed.
   * @param {boolean} [params.compressed=true] - Indicates if the recovered public key should be compressed.
   * @returns {Uint8Array} The recovered public key as a Uint8Array.
   */
  recoverPublicKey = ({
    signature,
    message,
    compressed = true,
  }: RecoverPublicKeyParams): Uint8Array => {
    return weierstrassRecoverPublicKey(this.curve, {
      signature,
      message,
      compressed,
    });
  };

  /**
   * Computes the shared secret for ECDH using a private key and a public key.
   *
   * @param {GetSharedSecretParams} params - An object containing the private and public keys.
   * @param {Uint8Array} params.privateKey - The private key as a Uint8Array.
   * @param {Uint8Array} params.publicKey - The public key as a Uint8Array.
   * @returns {Uint8Array} The computed shared secret as a Uint8Array.
   * @throws {Error} If the private key or public key is invalid.
   */
  getSharedSecret = ({
    privateKey,
    publicKey,
  }: GetSharedSecretParams): Uint8Array => {
    return weierstrassGetSharedSecret(this.curve, { privateKey, publicKey });
  };

  /**
   * Converts a private key to JWK format.
   *
   * @param {Uint8Array} privateKey - The private key to convert
   * @returns {JwkPrivateKey} The private key in JWK format
   * @throws {Error} If the private key is invalid
   */
  toJwkPrivateKey = (privateKey: Uint8Array): JwkPrivateKey => {
    return weierstrassToJwkPrivateKey(this.curve, privateKey);
  };

  /**
   * Converts a public key to JWK format.
   *
   * @param {Uint8Array} publicKey - The public key to convert
   * @returns {JwkPublicKey} The public key in JWK format
   * @throws {Error} If the public key is invalid
   */
  toJwkPublicKey = (publicKey: Uint8Array): JwkPublicKey => {
    return weierstrassToJwkPublickKey(this.curve, publicKey);
  };

  /**
   * Converts a JWK private key to raw format.
   *
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key to convert
   * @returns {Uint8Array} The private key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPrivateKey = (jwkPrivateKey: JwkPrivateKey): Uint8Array => {
    return weierstrassToRawPrivateKey(this.curve, jwkPrivateKey);
  };

  /**
   * Converts a JWK public key to raw format.
   *
   * @param {JwkPublicKey} jwkPublicKey - The JWK public key to convert
   * @returns {Uint8Array} The public key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPublicKey = (jwkPublicKey: JwkPublicKey): Uint8Array => {
    return weierstrassToRawPublicKey(this.curve, jwkPublicKey);
  };
}
