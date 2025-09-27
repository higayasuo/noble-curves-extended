import { createP384 } from '@/curves/weierstrass/p384';
import { Weierstrass } from './Weierstrass';
import { RandomBytes } from '@/curves/types';

/**
 * P-384 (secp384r1) curve implementation for digital signatures and ECDH.
 * This class provides a high-level interface for P-384 curve operations, including
 * key generation, validation, signing, verification, ECDH, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const p384 = new P384(randomBytes);
 * const privateKey = p384.randomPrivateKey();
 * const publicKey = p384.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = p384.sign({ message, privateKey });
 * const isValid = p384.verify({ signature, message, publicKey });
 * ```
 */
export class P384 extends Weierstrass {
  /**
   * Creates a new P-384 curve instance.
   *
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(randomBytes: RandomBytes) {
    super({
      curve: createP384(randomBytes),
      randomBytes,
      curveName: 'P-384',
      signatureAlgorithmName: 'ES384',
      keyByteLength: 48,
    });
  }
}
