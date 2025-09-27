import { createP521 } from '@/curves/weierstrass/p521';
import { Weierstrass } from './Weierstrass';
import { RandomBytes } from '@/curves/types';

/**
 * P-521 (secp521r1) curve implementation for digital signatures and ECDH.
 * This class provides a high-level interface for P-521 curve operations, including
 * key generation, validation, signing, verification, ECDH, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const p521 = new P521(randomBytes);
 * const privateKey = p521.randomPrivateKey();
 * const publicKey = p521.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = p521.sign({ message, privateKey });
 * const isValid = p521.verify({ signature, message, publicKey });
 * ```
 */
export class P521 extends Weierstrass {
  /**
   * Creates a new P-521 curve instance.
   *
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(randomBytes: RandomBytes) {
    super({
      curve: createP521(randomBytes),
      randomBytes,
      curveName: 'P-521',
      signatureAlgorithmName: 'ES512',
      keyByteLength: 66,
    });
  }
}
