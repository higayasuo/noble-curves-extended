import { CurveFn } from '@noble/curves/abstract/montgomery';
import {
  EcdhCurve,
  GetSharedSecretParams,
  JwkPrivateKey,
  JwkPublicKey,
  CurveName,
} from '@/unified/types';
import { RandomBytes } from '@/curves/types';
import { montgomeryRandomPrivateKey } from './montgomeryRandomPrivateKey';
import { montgomeryGetPublicKey } from './montgomeryGetPublicKey';
import { montgomeryToJwkPrivateKey } from './montgomeryToJwkPrivateKey';
import { montgomeryToJwkPublicKey } from './montgomeryToJwkPublicKey';
import { montgomeryToRawPrivateKey } from './montgomeryToRawPrivateKey';
import { montgomeryToRawPublicKey } from './montgomeryToRawPublicKey';
import { montgomeryGetSharedSecret } from './montgomeryGetSharedSecret';

type MontgomeryParams = {
  curve: CurveFn;
  randomBytes: RandomBytes;
  curveName: CurveName;
  keyByteLength: number;
};

/**
 * Montgomery implementation for Elliptic Curve Diffie-Hellman (ECDH) key exchange.
 * This class provides a high-level interface for Montgomery operations, including
 * key generation, validation, and shared secret computation.
 *
 * @example
 * ```typescript
 * const montgomery = new Montgomery({
 *   curve,
 *   randomBytes,
 *   curveName: 'X25519',
 *   keyByteLength: 32,
 * });
 * const privateKey = montgomery.randomPrivateKey();
 * const publicKey = montgomery.getPublicKey(privateKey);
 * const peerPublicKey = ...; // Uint8Array from peer
 * const sharedSecret = montgomery.getSharedSecret({ privateKey, publicKey: peerPublicKey });
 * ```
 */
export class Montgomery implements Readonly<EcdhCurve> {
  /** The underlying curve implementation */
  readonly curve: CurveFn;
  /** Function to generate random bytes */
  readonly randomBytes: RandomBytes;

  /** Curve identifier for Montgomery */
  readonly curveName: CurveName;

  /** Key byte length for Montgomery */
  readonly keyByteLength: number;

  /**
   * Creates a new Montgomery instance.
   *
   * @param {object} params - Constructor parameters
   * @param {CurveFn} params.curve - The curve implementation to use
   * @param {RandomBytes} params.randomBytes - Function to generate random bytes
   * @param {CurveName} params.curveName - Curve name identifier (e.g. 'X25519')
   * @param {number} params.keyByteLength - Expected byte length of keys (e.g. 32 for X25519)
   */
  constructor({
    curve,
    randomBytes,
    curveName,
    keyByteLength,
  }: MontgomeryParams) {
    this.curve = curve;
    this.randomBytes = randomBytes;
    this.curveName = curveName;
    this.keyByteLength = keyByteLength;
  }

  /**
   * Gets the underlying curve implementation.
   * This method allows access to the raw CurveFn implementation when needed.
   *
   * @returns {CurveFn} The underlying curve implementation
   */
  getCurve(): CurveFn {
    return this.curve;
  }

  /**
   * Generates a random private key for the Montgomery curve.
   *
   * @returns {Uint8Array} The random private key
   */
  randomPrivateKey(): Uint8Array {
    return montgomeryRandomPrivateKey(this.curve);
  }

  /**
   * Derives a public key from a private key.
   *
   * @param {Uint8Array} privateKey - The private key to derive from
   * @param {boolean} [compressed=true] - Whether to return a compressed public key
   * @returns {Uint8Array} The derived public key
   * @throws {Error} If the private key is invalid or uncompressed keys are requested
   */
  getPublicKey(privateKey: Uint8Array, compressed = true): Uint8Array {
    return montgomeryGetPublicKey(this.curve, privateKey, compressed);
  }

  /**
   * Computes a shared secret using ECDH.
   *
   * @param {GetSharedSecretParams} params - The parameters for shared secret computation
   * @param {Uint8Array} params.privateKey - The private key
   * @param {Uint8Array} params.publicKey - The public key
   * @returns {Uint8Array} The computed shared secret
   * @throws {Error} If either the private key or public key is invalid
   */
  getSharedSecret({
    privateKey,
    publicKey,
  }: GetSharedSecretParams): Uint8Array {
    return montgomeryGetSharedSecret(this.curve, { privateKey, publicKey });
  }

  /**
   * Converts a private key to JWK format.
   *
   * @param {Uint8Array} privateKey - The private key to convert
   * @returns {JwkPrivateKey} The private key in JWK format
   * @throws {Error} If the private key is invalid
   */
  toJwkPrivateKey(privateKey: Uint8Array): JwkPrivateKey {
    return montgomeryToJwkPrivateKey(
      this.curve,
      this.keyByteLength,
      this.curveName,
      privateKey,
    );
  }

  /**
   * Converts a public key to JWK format.
   *
   * @param {Uint8Array} publicKey - The public key to convert
   * @returns {JwkPublicKey} The public key in JWK format
   * @throws {Error} If the public key is invalid
   */
  toJwkPublicKey(publicKey: Uint8Array): JwkPublicKey {
    return montgomeryToJwkPublicKey(
      this.curve,
      this.keyByteLength,
      this.curveName,
      publicKey,
    );
  }

  /**
   * Converts a JWK private key to raw format.
   *
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key to convert
   * @returns {Uint8Array} The private key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPrivateKey(jwkPrivateKey: JwkPrivateKey): Uint8Array {
    return montgomeryToRawPrivateKey(this.curve, jwkPrivateKey);
  }

  /**
   * Converts a JWK public key to raw format.
   *
   * @param {JwkPublicKey} jwkPublicKey - The JWK public key to convert
   * @returns {Uint8Array} The public key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPublicKey(jwkPublicKey: JwkPublicKey): Uint8Array {
    return montgomeryToRawPublicKey(this.curve, jwkPublicKey);
  }
}
