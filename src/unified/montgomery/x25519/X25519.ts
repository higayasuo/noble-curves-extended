import { CurveFn } from '@noble/curves/abstract/montgomery';
import {
  Ecdh,
  GetSharedSecretParams,
  JwkPrivateKey,
  JwkPublicKey,
  CurveName,
} from '@/unified/types';
import { RandomBytes } from '@/curves/types';
import { x25519RandomPrivateKey } from './x25519RandomPrivateKey';
import { x25519GetPublicKey } from './x25519GetPublicKey';
import { x25519ToJwkPrivateKey } from './x25519ToJwkPrivateKey';
import { x25519ToJwkPublicKey } from './x25519ToJwkPublicKey';
import { x25519ToRawPrivateKey } from './x25519ToRawPrivateKey';
import { x25519ToRawPublicKey } from './x25519ToRawPublicKey';
import { x25519GetSharedSecret } from './x25519GetSharedSecret';

/**
 * X25519 implementation for Elliptic Curve Diffie-Hellman (ECDH) key exchange.
 * This class provides a high-level interface for X25519 operations, including
 * key generation, validation, and shared secret computation.
 *
 * @example
 * ```typescript
 * const x25519 = new X25519(curve, randomBytes);
 * const privateKey = x25519.randomPrivateKey();
 * const publicKey = x25519.getPublicKey(privateKey);
 * const peerPublicKey = ...; // Uint8Array from peer
 * const sharedSecret = x25519.getSharedSecret({ privateKey, publicKey: peerPublicKey });
 * ```
 */
export class X25519 implements Readonly<Ecdh> {
  /** The underlying curve implementation */
  readonly curve: CurveFn;
  /** Function to generate random bytes */
  readonly randomBytes: RandomBytes;

  /** Curve identifier for X25519 */
  curveName: CurveName = 'X25519';

  /**
   * Creates a new X25519 instance.
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
   * Generates a random private key for X25519.
   * The generated key is 32 bytes long and follows RFC 7748 specifications.
   *
   * @returns {Uint8Array} A 32-byte random private key
   */
  randomPrivateKey(): Uint8Array {
    return x25519RandomPrivateKey(this.curve);
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
    return x25519GetPublicKey(this.curve, privateKey, compressed);
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
    return x25519GetSharedSecret(this.curve, { privateKey, publicKey });
  }

  /**
   * Converts a private key to JWK format.
   *
   * @param {Uint8Array} privateKey - The private key to convert
   * @returns {JwkPrivateKey} The private key in JWK format
   * @throws {Error} If the private key is invalid
   */
  toJwkPrivateKey(privateKey: Uint8Array): JwkPrivateKey {
    return x25519ToJwkPrivateKey(this.curve, privateKey);
  }

  /**
   * Converts a public key to JWK format.
   *
   * @param {Uint8Array} publicKey - The public key to convert
   * @returns {JwkPublicKey} The public key in JWK format
   * @throws {Error} If the public key is invalid
   */
  toJwkPublicKey(publicKey: Uint8Array): JwkPublicKey {
    return x25519ToJwkPublicKey(this.curve, publicKey);
  }

  /**
   * Converts a JWK private key to raw format.
   *
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key to convert
   * @returns {Uint8Array} The private key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPrivateKey(jwkPrivateKey: JwkPrivateKey): Uint8Array {
    return x25519ToRawPrivateKey(this.curve, jwkPrivateKey);
  }

  /**
   * Converts a JWK public key to raw format.
   *
   * @param {JwkPublicKey} jwkPublicKey - The JWK public key to convert
   * @returns {Uint8Array} The public key in raw format
   * @throws {Error} If the JWK is invalid
   */
  toRawPublicKey(jwkPublicKey: JwkPublicKey): Uint8Array {
    return x25519ToRawPublicKey(this.curve, jwkPublicKey);
  }
}
